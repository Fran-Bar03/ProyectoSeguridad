using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using System.Security.Cryptography;

namespace Data.Helpers
{
    /// <summary>
    /// Helper estático para generar hash del User-Agent del navegador
    /// Se usa para prevenir que tokens JWT funcionen en navegadores diferentes
    /// </summary>
    public static class UserAgentHelper
    {

        /// <summary>
        /// Genera un hash SHA256 del User-Agent desde el HttpContext
        /// </summary>
        public static string GetUserAgentHash(HttpContext context)
        {
            var userAgent = context?.Request?.Headers["User-Agent"].ToString() ?? "unknown";
            return GetUserAgentHash(userAgent);
        }

        /// <summary>
        /// Genera un hash SHA256 del User-Agent string
        /// </summary>
        public static string GetUserAgentHash(string userAgent)
        {
            // Normalizar: quitar número de versión
            var normalized = System.Text.RegularExpressions.Regex
                .Replace(userAgent, @"\d+\.\d+", "X.X");

            using var sha256 = SHA256.Create();
            var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(normalized));
            return Convert.ToBase64String(hashBytes, 0, 16);
        }
    }
}
