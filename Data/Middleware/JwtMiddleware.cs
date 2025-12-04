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
        ///Metodo invocado por el pipeline de ASP.NET Core para cada request
        ///Valida el token Jwt, establece el usuario en el contexto y maneja redirecciones
        ///</summary>
        /// <param name="context">Contexto HTTP actual</param>
        /// <param name="jwtService">Servicio JWT inyectado por DI</param>
        /// <returns>Tarea asíncrona</returns>
        /// 

        public async Task Invoke(HttpContext context, JwtService jwtService)
        {

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

            // ===== CASO 1: Si es ruta pública, continuar sin verificar autenticación =====
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

            //  Es ruta protegida 

            // No hay token JWT en las cookies
            if (string.IsNullOrEmpty(token))
            {
                // Usuario no autenticado intentando acceder a área protegida
                // Redirigir a login con mensaje apropiado
                context.Response.Redirect("/Account/Login?message=NecesitaAutenticacion");
                return;
            }

            // Subcaso 3B: Hay token, validarlo usando el servicio JWT
            var principal = jwtService.ValidarToken(token);

            if (principal == null)
            {
                // Token inválido, corrupto o expirado
                // Eliminar cookie corrupta por seguridad
                context.Response.Cookies.Delete("jwt_token");

                // Redirigir a login indicando que el token expiró
                context.Response.Redirect("/Account/Login?message=TokenExpirado");
                return;
            }

            // Token válido, verificar si es el mismo navegador
            // Obtener hash del User-Agent almacenado en el token
            var userAgentHash = principal.FindFirst("UserAgentHash")?.Value;

            // Calcular hash del User-Agent actual
            var currentUserAgentHash = UserAgentHelper.GetUserAgentHash(context);

            if (userAgentHash != currentUserAgentHash)
            {
                // Diferente navegador: medida de seguridad contra robo de sesión
                context.Response.Cookies.Delete("jwt_token");

                // Redirigir a login con mensaje específico
                var redirectUrl = "/Account/Login?message=SesionInvalidaNavegador";
                context.Response.Redirect(redirectUrl);
                return;
            }

            // Token válido y mismo navegador

            // Detectar cambio de usuario (protección adicional)
            var currentUserId = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var previousUserId = context.Items["CurrentUserId"] as string;

            // Si cambió el usuario, limpiar sesión por seguridad
            if (previousUserId != null && previousUserId != currentUserId)
            {
                context.Response.Cookies.Delete("jwt_token");
                context.Response.Redirect("/Account/Login?message=CambioUsuarioDetectado");
                return;
            }

            // Guardar ID actual en contexto para futuras verificaciones
            context.Items["CurrentUserId"] = currentUserId;

            // establecer el usuario en el contexto HTTP
            // Esto permite que los controladores accedan a la información del usuario
            context.User = principal;

            // Redirigir usuarios ya autenticados que intentan acceder a login/registro
            // Evita que usuarios logueados vean páginas de autenticación
            if (path.StartsWith("/account/login") || path.StartsWith("/account/registro"))
            {
                context.Response.Redirect("/Encriptacion/Encriptar");
                return;
            }

            // ===== TODO VERIFICADO: Continuar con el siguiente middleware en el pipeline =====
            await _next(context);
        }
    }
}