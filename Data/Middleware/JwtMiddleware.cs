using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Data.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using Data.Helpers;
using System.Security.Claims;

namespace Data.Middleware
{
    /// <summary>
    /// Middleware personalizado para validar automáticamente tokens JWT en cada request.
    /// Este middleware se ejecuta en el pipeline HTTP y verifica la autenticación antes de
    /// que las requests lleguen a los controladores.
    /// MODIFICADO: Ahora detecta y maneja dispositivos móviles y tablets
    /// </summary>
    public class JwtMiddleware
    {
        private readonly RequestDelegate _next;

        /// <summary>
        /// Constructor del middleware JWT.
        /// </summary>
        /// <param name="next">Siguiente middleware en el pipeline</param>
        public JwtMiddleware(RequestDelegate next) => _next = next;


        ///<summary>
        /// Metodo invocado por el pipeline de ASP.NET Core para cada request
        /// Valida el token Jwt, establece el usuario en el contexto y maneja redirecciones
        /// MODIFICADO: Ahora incluye detección de dispositivos móviles y validación específica
        /// </summary>
        /// <param name="context">Contexto HTTP actual</param>
        /// <param name="jwtService">Servicio JWT inyectado por DI</param>
        /// <returns>Tarea asíncrona</returns>
        /// 
        public async Task Invoke(HttpContext context, JwtService jwtService)
        {
            // ======================================================================
            // DETECCIÓN DE DISPOSITIVO MÓVIL
            // ======================================================================
            // Obtener User-Agent para determinar tipo de dispositivo
            var userAgent = context.Request.Headers["User-Agent"].ToString();
            var esDispositivoMovil = EsDispositivoMovil(userAgent);

            // Guardar información del dispositivo en el contexto para uso posterior
            // Los controladores y servicios pueden acceder a esta información
            context.Items["EsDispositivoMovil"] = esDispositivoMovil;
            context.Items["UserAgent"] = userAgent;

            // Obtener el token JWT de las cookies
            var token = context.Request.Cookies["jwt_token"];

            // Obtener la ruta actual en minúsculas para comparación insensible a mayúsculas
            var path = context.Request.Path.Value?.ToLowerInvariant() ?? "/";

            // Definir rutas públicas y protegidas 

            // Rutas públicas: NO requieren autenticación
            // Estas son páginas a las que cualquier usuario puede acceder sin login
            var rutasPublicas = new[]
            {
                "/account/login",           // Formulario de login
                "/account/registro",        // Formulario de registro
                "/home/error",              // Página de error
                "/favicon.ico"              // Icono del sitio
            };

            // Verificar si la ruta actual es pública
            var esRutaPublica = rutasPublicas.Any(ruta => path.StartsWith(ruta));

            // Rutas protegidas: SI requieren autenticación
            // Estas son páginas que solo usuarios autenticados pueden ver
            var rutasProtegidas = new[]
            {
                "/encriptacion",            // Cualquier ruta bajo EncriptacionController
                "/account/vertoken",        // Ver información del token
                "/account/logout"           // Cerrar sesión (solo para autenticados)
            };

            // Verificar si la ruta actual está protegida
            var esRutaProtegida = rutasProtegidas.Any(ruta => path.StartsWith(ruta));

            // ======================================================================
            // LÓGICA DE ACCESO POR TIPO DE RUTA
            // ======================================================================

            //  Si es ruta pública, continuar sin verificar autenticación 
            // Permite acceso libre a login, registro y páginas de error
            if (esRutaPublica)
            {
                await _next(context);
                return;
            }

            // Si NO es ruta protegida ni pública
            // Esto permite acceso a rutas no definidas (como /, /Home, etc.)
            // Estas rutas pueden tener su propia lógica de autorización en los controladores
            if (!esRutaProtegida)
            {
                await _next(context);
                return;
            }

            // ======================================================================
            // ES RUTA PROTEGIDA - REQUIERE AUTENTICACIÓN
            // ======================================================================

            // No hay token JWT en las cookies
            if (string.IsNullOrEmpty(token))
            {
                // Usuario no autenticado intentando acceder a área protegida
                // Redirigir a login con mensaje apropiado y parámetro de dispositivo
                var redirectUrl = "/Account/Login?message=NecesitaAutenticacion";
                if (esDispositivoMovil)
                {
                    redirectUrl += "&dispositivo=mobile"; // Agregar parámetro para móviles
                }
                context.Response.Redirect(redirectUrl);
                return;
            }

            //  Hay token, validarlo usando el servicio JWT
            var principal = jwtService.ValidarToken(token);

            if (principal == null)
            {
                // Token inválido, corrupto o expirado
                // Eliminar cookie corrupta por seguridad
                context.Response.Cookies.Delete("jwt_token");

                // Redirigir a login indicando que el token expiró
                // Incluir parámetro de dispositivo si es móvil
                var redirectUrl = "/Account/Login?message=TokenInvalido";
                if (esDispositivoMovil)
                {
                    redirectUrl += "&dispositivo=mobile";
                }
                context.Response.Redirect(redirectUrl);
                return;
            }

            // ======================================================================
            // VALIDACIÓN DE DISPOSITIVO ADICIONAL PARA TOKENS VÁLIDOS
            // ======================================================================
            // Verificar que el token no se esté usando en un dispositivo diferente
            // al que se creó (protección contra uso cruzado de tokens)

            // Obtener hash del User-Agent almacenado en el token
            var userAgentClaim = principal.FindFirst("UserAgentHash")?.Value;

            // Generar hash del User-Agent actual
            var currentUserAgentHash = UserAgentHelper.GetUserAgentHash(context);

            // Si hay un hash en el token y no coincide con el actual
            if (!string.IsNullOrEmpty(userAgentClaim) && userAgentClaim != currentUserAgentHash)
            {
                // Usuario intentando usar token en diferente dispositivo/navegador
                // Eliminar cookie por seguridad
                context.Response.Cookies.Delete("jwt_token");

                // Redirigir con mensaje específico
                var redirectUrl = "/Account/Login?message=SesionInvalidaNavegador";
                if (esDispositivoMovil)
                {
                    redirectUrl += "&dispositivo=mobile";
                }
                context.Response.Redirect(redirectUrl);
                return;
            }

            // ======================================================================
            // DETECCIÓN DE CAMBIO DE USUARIO
            // ======================================================================
            // Verificar que no haya cambio de usuario durante la misma sesión

            // Obtener ID del usuario actual del token
            var currentUserId = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            // Obtener ID del usuario anterior del contexto (si existe)
            var previousUserId = context.Items["CurrentUserId"] as string;

            // Si cambió el usuario, limpiar sesión por seguridad
            if (previousUserId != null && previousUserId != currentUserId)
            {
                context.Response.Cookies.Delete("jwt_token");
                var redirectUrl = "/Account/Login?message=CambioUsuarioDetectado";
                if (esDispositivoMovil)
                {
                    redirectUrl += "&dispositivo=mobile";
                }
                context.Response.Redirect(redirectUrl);
                return;
            }

            // ======================================================================
            // CONFIGURACIÓN FINAL DEL CONTEXTO
            // ======================================================================

            // Guardar ID actual en contexto para futuras verificaciones
            context.Items["CurrentUserId"] = currentUserId;

            // Establecer el usuario en el contexto HTTP
            // Esto permite que los controladores accedan a la información del usuario
            context.User = principal;

            // ======================================================================
            // REDIRECCIÓN PARA USUARIOS YA AUTENTICADOS
            // ======================================================================
            // Redirigir usuarios ya autenticados que intentan acceder a login/registro
            // Evita que usuarios logueados vean páginas de autenticación

            if (path.StartsWith("/account/login") || path.StartsWith("/account/registro"))
            {
                var redirectUrl = "/Encriptacion/Encriptar";
                if (esDispositivoMovil)
                {
                    redirectUrl += "?dispositivo=mobile"; // Agregar parámetro para móviles
                }
                context.Response.Redirect(redirectUrl);
                return;
            }

            // ======================================================================
            // CONTINUAR CON EL PIPELINE
            // ======================================================================
            // Todo verificado correctamente, continuar con el siguiente middleware
            await _next(context);
        }

        // ======================================================================
        // FUNCIÓN AUXILIAR PARA DETECTAR DISPOSITIVOS MÓVILES
        // ======================================================================
        /// <summary>
        /// Detecta si el User-Agent corresponde a un dispositivo móvil o tablet
        /// Usa una lista de cadenas comunes en User-Agents de dispositivos móviles
        /// </summary>
        /// <param name="userAgent">Cadena User-Agent del navegador</param>
        /// <returns>True si es dispositivo móvil o tablet, False si es escritorio</returns>
        private bool EsDispositivoMovil(string userAgent)
        {
            if (string.IsNullOrEmpty(userAgent))
                return false;

            var userAgentLower = userAgent.ToLower();

            // Lista de dispositivos móviles y tablets
            // Incluye smartphones (Android, iPhone), tablets (iPad, Kindle) y navegadores móviles
            var dispositivosMoviles = new[]
            {
                "mobile", "android", "iphone", "ipad", "ipod",
                "blackberry", "windows phone", "webos", "opera mini",
                "iemobile", "kindle", "silk", "tablet", "touch"
            };

            return dispositivosMoviles.Any(dispositivo =>
                userAgentLower.Contains(dispositivo));
        }
    }
}