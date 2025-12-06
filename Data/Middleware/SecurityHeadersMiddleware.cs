using Microsoft.AspNetCore.Http;

namespace Data.Middleware
{
    public class SecurityHeadersMiddleware
    {
        private readonly RequestDelegate _next;

        public SecurityHeadersMiddleware(RequestDelegate next) => _next = next;

        public async Task Invoke(HttpContext context)
        {
            var path = context.Request.Path.ToString().ToLowerInvariant();

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
    }
}