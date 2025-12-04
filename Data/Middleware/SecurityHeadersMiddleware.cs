using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection.PortableExecutable;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace Data.Middleware
{
    /// <summary>
    /// Middleware para agregar headers de seguridad HTTP a todas las respuestas.
    /// Estos headers protegen contra varios tipos de ataques web comunes como XSS, clickjacking, etc.
    public class SecurityHeadersMiddleware
    {
        private readonly RequestDelegate _next;

        ///<sumary>
        ///Constructor del middleware de headers de seguridad
        ///</sumary>
        /// <param name="next">Siguiente middleware en el pipeline</param>

        public SecurityHeadersMiddleware(RequestDelegate next) => _next = next;


        ///<summary>
        /// Metodo invocado por el pipeline para cada request
        /// Agrega headers de seguridad a la respuesta HTTP
        ///</summary>
        ///<param name="context">Contexto Http actualk</param>
        ///<return>Tarea asincrona</return>
        public async Task Invoke(HttpContext context)
        {
            var path = context.Request.Path;
            var rutasProtegidas = new[]
            {
                "/Encriptacion",
                "/Account/VerToken",
                "/Account/Logout"
            };

            var esRutaProtegida = rutasProtegidas.Any(ruta => path.StartsWithSegments(ruta));

            //HEADERS NUCLEARES ANTI-CACHÉ 
            if (esRutaProtegida)
            {
                // para todos los navegadores
                context.Response.Headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0, private, no-transform";
                context.Response.Headers["Pragma"] = "no-cache";
                context.Response.Headers["Expires"] = "Mon, 01 Jan 1990 00:00:00 GMT"; // Fecha en pasado

                // Headers adicionales para Chrome/Edge
                context.Response.Headers["Vary"] = "User-Agent, Accept-Encoding, Cookie, Authorization";

                // Para Safari
                context.Response.Headers["Surrogate-Control"] = "no-store";

                // Para Firefox
                context.Response.Headers["X-Content-Type-Options"] = "nosniff";

                // Para IE/Edge legacy
                context.Response.Headers["X-UA-Compatible"] = "IE=Edge,chrome=1";

                // Header extra para CloudFlare/CDN
                context.Response.Headers["CDN-Cache-Control"] = "no-store";

                // ===== NUEVO: HEADER ESPECÍFICO PARA BLOQUEAR "ATRÁS" =====
                context.Response.Headers["Cache-Control"] += ", no-cache=\"Set-Cookie\"";

                // Header para evitar almacenamiento en caché de navegación
                context.Response.Headers["Cache-Control"] += ", no-store, must-revalidate";
            }
            else if (path.StartsWithSegments("/Account/Login") || path.StartsWithSegments("/Account/Registro"))
            {
                // ===== NUEVO: PARA PÁGINAS DE LOGIN/REGISTRO TAMBIÉN =====
                // Esto evita que después de logout, el usuario pueda volver con "Atrás"
                context.Response.Headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0";
                context.Response.Headers["Pragma"] = "no-cache";
                context.Response.Headers["Expires"] = "0";
            }

            // Headers de seguridad estándar
            context.Response.Headers["X-Frame-Options"] = "DENY";
            context.Response.Headers["X-XSS-Protection"] = "1; mode=block";
            context.Response.Headers["Referrer-Policy"] = "strict-origin-when-cross-origin";

            await _next(context);
        }
    }
}