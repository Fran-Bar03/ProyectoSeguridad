using Microsoft.AspNetCore.Http;

namespace Data.Middleware
{
    /// <summary>
    /// Middleware para agregar headers de seguridad HTTP
    /// Protege contra ataques comunes y mejora la seguridad de la aplicación
    /// MODIFICADO: Ahora incluye headers específicos para dispositivos móviles
    /// </summary>
    public class SecurityHeadersMiddleware
    {
        private readonly RequestDelegate _next;

        /// <summary>
        /// Constructor del middleware de headers de seguridad
        /// </summary>
        /// <param name="next">Siguiente middleware en el pipeline</param>
        public SecurityHeadersMiddleware(RequestDelegate next) => _next = next;

        /// <summary>
        /// Método invocado para cada request
        /// Agrega headers de seguridad según el tipo de contenido y dispositivo
        /// MODIFICADO: Headers específicos para dispositivos móviles y mejor CSP
        /// </summary>
        /// <param name="context">Contexto HTTP actual</param>
        /// <returns>Tarea asíncrona</returns>
        public async Task Invoke(HttpContext context)
        {
            var path = context.Request.Path.ToString().ToLowerInvariant();

            // ======================================================================
            // DETECCIÓN DE DISPOSITIVO MÓVIL
            // ======================================================================
            // Obtener User-Agent para determinar tipo de dispositivo
            var userAgent = context.Request.Headers["User-Agent"].ToString();
            var esDispositivoMovil = EsDispositivoMovil(userAgent);

            // ======================================================================
            // HEADERS DE SEGURIDAD ESPECÍFICOS PARA DISPOSITIVOS MÓVILES
            // ======================================================================
            if (esDispositivoMovil)
            {
                // -----------------------------------------------------------
                // X-Content-Type-Options: Prevenir MIME type sniffing
                // -----------------------------------------------------------
                // En móviles, es crucial prevenir que navegadores "adivinen" tipos de contenido
                // Previene ataques donde archivos maliciosos se disfrazan de inofensivos
                context.Response.Headers["X-Content-Type-Options"] = "nosniff";

                // -----------------------------------------------------------
                // X-Permitted-Cross-Domain-Policies: Controlar políticas entre dominios
                // -----------------------------------------------------------
                // Especialmente importante para móviles que pueden cargar contenido cruzado
                // Bloquea políticas que permiten carga de contenido desde otros dominios
                context.Response.Headers["X-Permitted-Cross-Domain-Policies"] = "none";

                // -----------------------------------------------------------
                // Content-Security-Policy (CSP) MEJORADO PARA MÓVILES
                // -----------------------------------------------------------
                // Política de seguridad de contenido más estricta para dispositivos móviles
                // Previene ataques XSS (Cross-Site Scripting) e inyección de contenido
                context.Response.Headers["Content-Security-Policy"] =
                    "default-src 'self'; " +                    // Por defecto, solo contenido propio
                    "script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; " + // Scripts permitidos
                    "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; " +  // Estilos permitidos
                    "img-src 'self' data: https:; " +          // Imágenes desde self, data URLs y HTTPS
                    "font-src 'self' https://cdn.jsdelivr.net; " + // Fuentes permitidas
                    "connect-src 'self'; " +                   // Conexiones (AJAX) solo a self
                    "frame-ancestors 'none';";                 // No permitir iframes

                // -----------------------------------------------------------
                // Permissions-Policy (antes Feature-Policy)
                // -----------------------------------------------------------
                // Controla qué APIs del navegador pueden usarse
                // Importante para móviles con sensores y hardware especial
                context.Response.Headers["Permissions-Policy"] =
                    "camera=(), microphone=(), geolocation=(), payment=()";
            }

            // ===========================================
            // HEADERS GENERALES: ¿PARA QUÉ SIRVEN?
            // ===========================================
            // Son instrucciones HTTP que el servidor envía al navegador
            // Controlan: seguridad, caché, compatibilidad
            // Objetivo: Prevenir que navegador muestre datos viejos/cacheados

            // Aplicar headers intensivos solo en páginas SENSIBLES
            // (donde hay datos de usuario o se maneja información crítica)
            if (context.User?.Identity?.IsAuthenticated == true ||
                path.Contains("/encriptacion") ||
                path.Contains("/account/vertoken"))
            {
                // -----------------------------------------------------------
                // Cache-Control: Controla el almacenamiento temporal (caché)
                // -----------------------------------------------------------
                // Problema: Navegador guarda páginas para cargar más rápido
                // Riesgo: Usuario B podría ver datos de Usuario A al usar "Atrás"
                // Solución: Desactivar completamente el caché en páginas sensibles
                context.Response.Headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0, private, no-transform";
                // no-store: NO guardar en disco
                // no-cache: Validar siempre con servidor
                // max-age=0: Expirar inmediatamente
                // private: Solo caché local (no en proxies)
                // no-transform: No modificar contenido

                // -----------------------------------------------------------
                // Pragma: Compatibilidad con navegadores antiguos
                // -----------------------------------------------------------
                // Para Internet Explorer y versiones antiguas de otros navegadores
                // Hace lo mismo que Cache-Control pero en HTTP/1.0
                context.Response.Headers["Pragma"] = "no-cache";

                // -----------------------------------------------------------
                // Expires: Fecha de expiración forzada
                // -----------------------------------------------------------
                // Establece fecha de expiración en el pasado (1990)
                // Navegador ve "esto ya expiró" y no usa versión cacheada
                context.Response.Headers["Expires"] = "Mon, 01 Jan 1990 00:00:00 GMT";

                // -----------------------------------------------------------
                // Vary: Manejo de contenido variable
                // -----------------------------------------------------------
                // Indica que la página puede cambiar según cookies/usuario
                // Navegador guarda versiones separadas por usuario
                context.Response.Headers["Vary"] = "*";

                // -----------------------------------------------------------
                // Surrogate-Control: Control para proxies/Safari
                // -----------------------------------------------------------
                // Safari y algunos proxies tienen caché propio
                // Este header los desactiva específicamente
                context.Response.Headers["Surrogate-Control"] = "no-store";

                // -----------------------------------------------------------
                // Refuerzos específicos
                // -----------------------------------------------------------
                // Cuando hay cookies (Set-Cookie), invalidar caché automáticamente
                // Útil cuando usuario cambia (cookies diferentes)
                context.Response.Headers["Cache-Control"] += ", no-cache=\"Set-Cookie\"";

                // Refuerzo adicional: asegurar no-store y must-revalidate
                context.Response.Headers["Cache-Control"] += ", no-store, must-revalidate";
            }
            // ---------------------------------------------------------------
            // Headers para páginas públicas (login/registro)
            // ---------------------------------------------------------------
            // También necesitan anti-caché pero menos agresivo
            // Para evitar que después de logout se vea pantalla de login cacheada
            else if (path.Contains("/account/login") || path.Contains("/account/registro"))
            {
                // Versión simplificada para páginas públicas
                context.Response.Headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0";
                context.Response.Headers["Pragma"] = "no-cache";
                context.Response.Headers["Expires"] = "0";
            }

            // ===========================================
            // HEADERS DE SEGURIDAD GENERALES
            // ===========================================
            // Se aplican a TODAS las páginas siempre

            // -----------------------------------------------------------
            // X-Frame-Options: Protección contra clickjacking
            // -----------------------------------------------------------
            // Evita que la página se cargue dentro de un iframe
            // Prevención: Ataques donde engañan al usuario para hacer clic
            context.Response.Headers["X-Frame-Options"] = "DENY";
            // "DENY": Prohibe completamente cargar en iframe

            // -----------------------------------------------------------
            // X-XSS-Protection: Filtro contra XSS en navegadores antiguos
            // -----------------------------------------------------------
            // Activa el filtro contra scripts maliciosos en Chrome/IE
            // mode=block: Si detecta XSS, bloquea toda la página
            context.Response.Headers["X-XSS-Protection"] = "1; mode=block";

            // -----------------------------------------------------------
            // Referrer-Policy: Control de información de referencia
            // -----------------------------------------------------------
            // Controla qué información envía el navegador al cambiar de página
            // strict-origin-when-cross-origin: 
            // - Misma página: envía toda la URL
            // - Página diferente: solo envía origen (no ruta completa)
            context.Response.Headers["Referrer-Policy"] = "strict-origin-when-cross-origin";

            await _next(context);
        }

        // ======================================================================
        // FUNCIÓN AUXILIAR PARA DETECTAR DISPOSITIVOS MÓVILES
        // ======================================================================
        /// <summary>
        /// Detecta si el User-Agent corresponde a un dispositivo móvil o tablet
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
    }
}