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
    /// MODIFICADO: Ahora incluye detección temprana de scripts automatizados
    /// </summary>
    public class JwtMiddleware
    {
        private readonly RequestDelegate _next;

        /// <summary>
        /// Constructor del middleware JWT.
        /// </summary>
        /// <param name="next">Siguiente middleware en el pipeline</param>
        public JwtMiddleware(RequestDelegate next) => _next = next;


        /// <summary>
        /// Metodo invocado por el pipeline de ASP.NET Core para cada request
        /// Valida el token Jwt, establece el usuario en el contexto y maneja redirecciones
        /// MODIFICADO: Incluye detección temprana y bloqueo de scripts automatizados
        /// </summary>
        /// <param name="context">Contexto HTTP actual</param>
        /// <param name="jwtService">Servicio JWT inyectado por DI</param>
        /// <returns>Tarea asíncrona</returns>
        /// 
        public async Task Invoke(HttpContext context, JwtService jwtService)
        {
            // ======================================================================
            // DETECCIÓN TEMPRANA DE SCRIPTS AUTOMATIZADOS - PRIMERA LINEA DE DEFENSA
            // ======================================================================
            // Antes de procesar cualquier petición, verificar si es un script de ataque
            var userAgent = context.Request.Headers["User-Agent"].ToString();

            // Verificar si el User-Agent corresponde a un script de ataque conocido
            if (EsScriptDeAtaque(userAgent))
            {
                // LOG DETALLADO PARA MONITOREO DE ATAQUES
                var ipAddress = context.Connection.RemoteIpAddress?.ToString() ?? "IP_DESCONOCIDA";
                Console.WriteLine($"BLOQUEO INMEDIATO DE SCRIPT: IP={ipAddress}, UserAgent={userAgent}");

                // Respuesta que simula éxito pero bloquea el acceso
                // Esto confunde a los scripts automatizados
                context.Response.StatusCode = 403; // Forbidden
                await context.Response.WriteAsync(@"
                <html>
                <head>
                    <title>Acceso Denegado</title>
                    <meta name='robots' content='noindex,nofollow'>
                </head>
                <body>
                    <!-- Acceso bloqueado por seguridad -->
                </body>
                </html>");

                // DETENER el pipeline aquí - no procesar más esta petición
                return;
            }

            // ======================================================================
            // DETECCIÓN DE DISPOSITIVO MÓVIL (código existente)
            // ======================================================================
            var esDispositivoMovil = EsDispositivoMovil(userAgent);

            // Guardar información del dispositivo en el contexto para uso posterior
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
            var dispositivosMoviles = new[]
            {
                "mobile", "android", "iphone", "ipad", "ipod",
                "blackberry", "windows phone", "webos", "opera mini",
                "iemobile", "kindle", "silk", "tablet", "touch"
            };

            return dispositivosMoviles.Any(dispositivo =>
                userAgentLower.Contains(dispositivo));
        }

        // ======================================================================
        // FUNCIÓN NUEVA: DETECTAR SCRIPTS DE ATAQUE ESPECÍFICOS
        // ======================================================================
        /// <summary>
        /// Detecta scripts específicos de ataque masivo (como el que recibiste)
        /// Basado en patrones específicos de herramientas de automatización masiva
        /// </summary>
        /// <param name="userAgent">Cadena User-Agent a analizar</param>
        /// <returns>True si es script de ataque, False si es legítimo</returns>
        private bool EsScriptDeAtaque(string userAgent)
        {
            if (string.IsNullOrEmpty(userAgent))
                return true; // Sin User-Agent = muy sospechoso

            var userAgentLower = userAgent.ToLower();

            // Permitir User-Agents locales comunes
            if (userAgentLower.Contains("localhost") ||
                userAgentLower.Contains("127.0.0.1") ||
                userAgentLower.Contains("::1"))
            {
                Console.WriteLine($"User-Agent local permitido: {userAgent}");
                return false;
            }

            // ======================================================================
            // LISTA COMPLETA DE NAVEGADORES PERMITIDOS (ACTUALIZADA)
            // ======================================================================
            var navegadoresPermitidos = new[]
            {
        // Firefox y derivados
        "mozilla", "firefox", "gecko", "seamonkey", "waterfox",
        "librewolf", "tor browser", "palemoon", "basilisk",
        
        // Chrome/Chromium y derivados
        "chrome", "chromium", "crios", "brave", "vivaldi",
        "edgechromium", "edg", "edga", "edgios", "whale",
        "samsungbrowser", "opera", "opr", "yandexbrowser",
        "uc browser", "maxthon", "qqbrowser", "duckduckgo",
        
        // Safari y WebKit
        "safari", "webkit", "applewebkit", "version",
        
        // Internet Explorer y antiguos
        "msie", "trident", "iemobile", "internet explorer",
        
        // Navegadores móviles
        "mobile", "android", "iphone", "ipad", "ipod",
        "windows phone", "blackberry", "webos", "kindle",
        "playbook", "series", "smarttv", "tv", "tablet",
        
        // Headless browsers (usados en testing)
        "headlesschrome", "phantomjs", "slimerjs",
        
        // Herramientas de desarrollo/testing
        "postmanruntime", "insomnia", "thunder client",
        "swagger", "openapi", "restclient", "httpclient",
        "fiddler", "charles", "paw",
        
        // Bots legítimos (motores de búsqueda)
        "googlebot", "bingbot", "slurp", "duckduckbot",
        "baiduspider", "yandexbot", "facebookexternalhit",
        "twitterbot", "linkedinbot", "telegrambot",
        "discordbot", "slackbot", "whatsapp",
        
        // Monitores y herramientas legítimas
        "uptimerobot", "pingdom", "newrelic", "datadog",
        "statuscake", "site24x7", "gtmetrix", "pagespeed",
        
        // Librerías HTTP legítimas
        "okhttp", "axios", "fetch", "got", "request",
        "unirest", "superagent", "node-fetch",
        
        // Otros permitidos
        "electron", "nwjs", "cef", "webview"
    };

            // Verificar si es un navegador/h herramienta permitida
            foreach (var navegador in navegadoresPermitidos)
            {
                if (userAgentLower.Contains(navegador))
                {
                    Console.WriteLine($"✅ Navegador/herramienta permitida detectada: '{navegador}'");
                    return false; // NO es script de ataque
                }
            }

            // ======================================================================
            // PATRONES DE SCRIPTS DE ATAQUE (SOLO ESTOS SERÁN BLOQUEADOS)
            // ======================================================================
            var patronesAtaqueMasivo = new[]
            {
        // Herramientas de hacking/ataque específicas
        "sqlmap", "nikto", "nmap", "hydra", "medusa",
        "patator", "brutus", "dirb", "gobuster", "ffuf",
        "wfuzz", "arjun", "xsstrike", "commix", "wapiti",
        "skipfish", "w3af", "zap", "burpsuite", "nessus",
        "openvas", "acunetix", "netsparker", "appscan",
        "arachni", "vega", "skipfish",
        
        // Network scanners maliciosos
        "masscan", "zmap", "zgrab", "unicornscan",
        "angry ip scanner", "advanced port scanner",
        
        // Scrapers maliciosos (no legítimos)
        "scrapy/1.", "scrapy/2.", "scrapy/0.",
        "beautifulsoup", "lxml", "htmlparser",
        "mechanize", "goutte", "simplehtmldom",
        
        // Fuerza bruta específica
        "john the ripper", "hashcat", "ophcrack",
        "rainbowcrack", "cain and abel",
        
        // Scripts personalizados maliciosos
        "custom script", "mybot", "autobot", "attackbot",
        "hackbot", "exploit", "vulnerability scanner",
        "security scanner", "penetration test",
        
        // Sin User-Agent o claramente falsos
        "", "default", "unknown", "test", "fake",
        "dummy", "placeholder", "example", "sample",
        
        // Patrones numéricos de ataque masivo
        @"^user\d+$", @"^test\d+$", @"^client\d+$",
        @"^bot\d+$", @"^scan\d+$", @"^attack\d+$",
        
        // IP como User-Agent
        @"^\d+\.\d+\.\d+\.\d+$",
        
        // Caracteres especiales/inyección
        @"<script", @"javascript:", @"onload=",
        @"onerror=", @"onclick=", @"alert\(",
        @"document\.", @"window\.", @"eval\(",
        
        // Muy cortos y sospechosos
        @"^.{1,5}$" // 1-5 caracteres solamente
    };

            foreach (var patron in patronesAtaqueMasivo)
            {
                if (System.Text.RegularExpressions.Regex.IsMatch(userAgentLower, patron))
                {
                    Console.WriteLine($" SCRIPT DE ATAQUE DETECTADO: '{patron}'");
                    Console.WriteLine($"   User-Agent completo: {userAgent}");
                    return true; // BLOQUEAR
                }
            }

            // ======================================================================
            // DETECCIÓN AVANZADA POR COMPORTAMIENTO
            // ======================================================================

            // User-Agent demasiado largo (posible inyección)
            if (userAgent.Length > 1000)
            {
                Console.WriteLine($" User-Agent demasiado largo ({userAgent.Length} chars) - posible inyección");
                return true;
            }

            // Solo números y puntos (posible IP o versión)
            if (System.Text.RegularExpressions.Regex.IsMatch(userAgent, @"^[\d\.]+$"))
            {
                Console.WriteLine($" User-Agent solo con números/puntos: {userAgent}");
                return true;
            }

            // Solo letras repetidas
            if (System.Text.RegularExpressions.Regex.IsMatch(userAgent, @"^(.)\1+$"))
            {
                Console.WriteLine($" User-Agent con letras repetidas: {userAgent}");
                return true;
            }

            // ======================================================================
            // SI LLEGA AQUÍ, ES PROBABLEMENTE UN CLIENTE DESCONOCIDO PERTO NO MALICIOSO
            // ======================================================================
            Console.WriteLine($" User-Agent no reconocido pero PERMITIDO: {userAgent}");
            Console.WriteLine($"   Longitud: {userAgent.Length}");
            Console.WriteLine($"   Contiene navegadores conocidos: {navegadoresPermitidos.Any(n => userAgentLower.Contains(n))}");

            // Por defecto: PERMITIR (mejor permitir un falso negativo que bloquear usuario legítimo)
            return false;
        }
    }
}