using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Data.Interfaces;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Models;
using Data.Helpers;

namespace Data.Services
{
    /// <summary>
    /// Servicio para manejar la generación y validación de tokens JWT (JSON Web Tokens).
    /// Implementa autenticación stateless con tokens seguros que incluyen claims del usuario.
    /// Los tokens JWT permiten autenticación sin necesidad de almacenar estado en el servidor.
    /// MODIFICADO: Ahora incluye información del dispositivo móvil en los tokens
    /// </summary>
    public class JwtService : IJwtService
    {
        private readonly IConfiguration _configuration;
        private readonly IHttpContextAccessor _httpContextAccessor;

        /// <summary>
        /// Constructor del servicio JWT
        /// Inicializa la configuración necesaria para generar y validar tokens
        /// </summary>
        /// <param name="configuration">Instancia de IConfiguration para acceder a settings JWT</param>
        /// <param name="httpContextAccessor">Acceso al HttpContext para obtener información del dispositivo</param>
        public JwtService(IConfiguration configuration, IHttpContextAccessor httpContextAccessor)
        {
            _configuration = configuration;
            _httpContextAccessor = httpContextAccessor;
        }


        /// <summary>
        /// Genera un token JWT para un usuario autenticado.
        /// Incluye claims con información del usuario y configuración de seguridad.
        /// MODIFICADO: Ahora incluye información del dispositivo (User-Agent hash y tipo)
        /// </summary>
        /// <param name="usuario">Objeto Usuario con la información para incluir en el token</param>
        /// <returns>Token JWT firmado como string</returns>
        public string GenerarJwtToken(UsuarioModel usuario)
        {
            // ======================================================================
            // OBTENER INFORMACIÓN DEL DISPOSITIVO
            // ======================================================================
            var currentUserAgentHash = UserAgentHelper.GetUserAgentHash(_httpContextAccessor.HttpContext);
            var esDispositivoMovil = EsDispositivoMovil(_httpContextAccessor.HttpContext);

            // ======================================================================
            // OBTENER TIMESTAMP EN HORA DE HERMOSILLO
            // ======================================================================
            // Obtener la hora actual en Hermosillo
            var hermosilloNow = TimeZoneHelper.NowInHermosillo();

            // Convertir a UTC para el timestamp Unix
            var hermosilloAsUtc = TimeZoneInfo.ConvertTimeToUtc(
                hermosilloNow,
                TimeZoneHelper.GetHermosilloTimeZone()
            );

            // Obtener timestamp Unix (en UTC)
            var timestampHermosillo = new DateTimeOffset(hermosilloAsUtc).ToUnixTimeSeconds();

            // Para debugging: obtener también timestamp UTC normal
            var timestampUtc = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            // ======================================================================
            // CREAR CLAIMS CON TIMESTAMP CORRECTO
            // ======================================================================
            var claims = new List<Claim>
        {
        // Claims básicos del usuario
        new Claim(ClaimTypes.NameIdentifier, usuario.IdUsuario.ToString()),
        new Claim(ClaimTypes.Email, usuario.Email),
        new Claim(ClaimTypes.Name, usuario.Nombre),
        new Claim("NombreCompleto", $"{usuario.Nombre} {usuario.ApellidoPaterno} {usuario.ApellidoMaterno}"),
        
        // Claims técnicos del token - USANDO TIMESTAMP DE HERMOSILLO
        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        new Claim(JwtRegisteredClaimNames.Iat,
            timestampHermosillo.ToString(),  // Usar timestamp de Hermosillo
            ClaimValueTypes.Integer64),
        
        // Información adicional para debug (opcional)
        new Claim("TimeZone", "America/Hermosillo"),
        new Claim("GeneratedAtLocal", hermosilloNow.ToString("yyyy-MM-ddTHH:mm:ss")),
        
        // Claims de seguridad para dispositivos móviles
        new Claim("UserAgentHash", currentUserAgentHash),
        new Claim("Dispositivo", esDispositivoMovil ? "mobile" : "desktop")
        };

            // ======================================================================
            // RESTANTE DEL CÓDIGO SIN CAMBIOS
            // ======================================================================
            var llave = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(
                Environment.GetEnvironmentVariable("JWT__Key") ??
                _configuration["Jwt:Key"] ??
                throw new Exception("JWT Key no configurada")
            ));

            var credenciales = new SigningCredentials(llave, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: Environment.GetEnvironmentVariable("JWT__Issuer") ??
                        _configuration["Jwt:Issuer"] ?? "SecurityApp",
                audience: Environment.GetEnvironmentVariable("JWT__Audience") ??
                         _configuration["Jwt:Audience"] ?? "SecurityUsers",
                claims: claims,
                expires: null, // Sin expiración
                signingCredentials: credenciales);

            // DEBUG: Log para verificar el timestamp
            Console.WriteLine($"Token generado - Hermosillo: {hermosilloNow:HH:mm:ss}, " +
                             $"Timestamp: {timestampHermosillo}, " +
                             $"UTC: {DateTime.UtcNow:HH:mm:ss}");

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        /// <summary>
        /// Valida un token JWT y retorna el principal de claims si es válido.
        /// Verifica la firma, emisor, audiencia y fecha de expiración del token.
        /// MODIFICADO: Ahora también valida la firma y estructura básica del token
        /// </summary>
        /// <param name="token">Token JWT a validar</param>
        /// <returns>ClaimsPrincipal si el token es válido, null en caso contrario</returns>
        public ClaimsPrincipal ValidarToken(string token)
        {
            try
            {
                // Crear manejador de tokens JWT
                var tokenHandler = new JwtSecurityTokenHandler();

                // Obtener clave de firma desde configuración
                var llave = Encoding.UTF8.GetBytes(
                    Environment.GetEnvironmentVariable("JWT__Key") ??
                    _configuration["Jwt:Key"] ??
                    throw new Exception("JWT Key no configurada"));

                // ======================================================================
                // CONFIGURAR PARÁMETROS DE VALIDACIÓN
                // ======================================================================
                var ValidadcionParametros = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,                         // Validar la firma del token
                    IssuerSigningKey = new SymmetricSecurityKey(llave),     // Clave para validar firma
                    ValidateIssuer = true,                                  // Validar el emisor
                    ValidateAudience = true,                                // Validar la audiencia
                    ValidateLifetime = false,                               // No validar fecha de expiración (tokens indefinidos)
                    ValidIssuer = Environment.GetEnvironmentVariable("JWT__Issuer") ??
                                  _configuration["Jwt:Issuer"] ?? "SecurityApp", // Emisor válido
                    ValidAudience = Environment.GetEnvironmentVariable("JWT__Audience") ??
                                    _configuration["Jwt:Audience"] ?? "SecurityUsers", // Audiencia valida
                    ClockSkew = TimeSpan.Zero                               // Sin tolerancia para expiración
                };

                // ======================================================================
                // VALIDAR EL TOKEN
                // ======================================================================
                // ValidateToken verifica: firma, emisor, audiencia y estructura del token
                // Si todo es correcto, retorna un ClaimsPrincipal con la información del usuario
                return tokenHandler.ValidateToken(token, ValidadcionParametros, out _);
            }
            catch
            {
                // Si la validación falla, retornar null
                // Esto puede ocurrir por: token expirado, firma inválida, formato incorrecto
                return null;
            }
        }

        // ======================================================================
        // FUNCIÓN AUXILIAR PARA DETECTAR DISPOSITIVOS MÓVILES
        // ======================================================================
        /// <summary>
        /// Detecta si la petición proviene de un dispositivo móvil o tablet
        /// basado en el User-Agent del HttpContext
        /// </summary>
        /// <param name="context">HttpContext con la información de la petición</param>
        /// <returns>True si es dispositivo móvil o tablet, False si es escritorio</returns>
        private bool EsDispositivoMovil(HttpContext context)
        {
            // Obtener User-Agent del request
            var userAgent = context?.Request?.Headers["User-Agent"].ToString() ?? "";
            var userAgentLower = userAgent.ToLower();

            // Lista de cadenas que identifican dispositivos móviles y tablets
            var dispositivosMoviles = new[]
            {
                "mobile", "android", "iphone", "ipad", "ipod",
                "blackberry", "windows phone", "webos", "opera mini",
                "iemobile", "kindle", "silk", "tablet", "touch"
            };

            // Verificar si el User-Agent contiene alguna cadena de dispositivo móvil
            return dispositivosMoviles.Any(dispositivo =>
                userAgentLower.Contains(dispositivo));
        }
    }
}