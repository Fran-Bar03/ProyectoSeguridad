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
            // Generar hash del User-Agent para verificar que el token se use
            // en el mismo dispositivo/navegador donde se creó
            var currentUserAgentHash = UserAgentHelper.GetUserAgentHash(_httpContextAccessor.HttpContext);

            // Detectar si es dispositivo móvil basado en el User-Agent
            var esDispositivoMovil = EsDispositivoMovil(_httpContextAccessor.HttpContext);


            // ======================================================================
            // CREAR CLAIMS (INFORMACIÓN DEL USUARIO Y DISPOSITIVO)
            // ======================================================================
            // Los claims son fragmentos de información sobre el usuario
            // Se incluyen en el token y pueden ser leídos posteriormente
            var claims = new List<Claim>
            {
                // Claims básicos del usuario
                new Claim(ClaimTypes.NameIdentifier, usuario.IdUsuario.ToString()),    // ID unico del usuario
                new Claim(ClaimTypes.Email, usuario.Email),                            // Email del usuario
                new Claim(ClaimTypes.Name, usuario.Nombre),                            // Nombre del usuario
                new Claim("NombreCompleto", $"{usuario.Nombre} {usuario.ApellidoPaterno} {usuario.ApellidoMaterno}"), // Nombre completo
                
                // Claims técnicos del token
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),     // ID unico del token
                new Claim(JwtRegisteredClaimNames.Iat,
                    DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(),              // Fecha de creación
                    ClaimValueTypes.Integer64),
                
                // Claims de seguridad para dispositivos móviles
                new Claim("UserAgentHash", currentUserAgentHash), // Hash del dispositivo/navegador
                new Claim("Dispositivo", esDispositivoMovil ? "mobile" : "desktop") // Tipo de dispositivo
            };


            // ======================================================================
            // CONFIGURAR CLAVE DE FIRMA
            // ======================================================================
            // Crear clave simetrica para firmar el token usando la clave secreta de la configuracion
            // La firma asegura que el token no ha sido alterado
            var llave = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(
                Environment.GetEnvironmentVariable("JWT__Key") ??
                _configuration["Jwt:Key"] ??
                throw new Exception("JWT Key no configurada")
            ));

            // Crear credenciales de firma usando algoritmo HMAC-SHA256
            var credenciales = new SigningCredentials(llave, SecurityAlgorithms.HmacSha256);


            // ======================================================================
            // CREAR EL TOKEN JWT
            // ======================================================================
            var token = new JwtSecurityToken(
                issuer: Environment.GetEnvironmentVariable("JWT__Issuer") ??
                        _configuration["Jwt:Issuer"] ?? "SecurityApp",      // Emisor del token
                audience: Environment.GetEnvironmentVariable("JWT__Audience") ??
                         _configuration["Jwt:Audience"] ?? "SecurityUsers", // Audiencia destinataria
                claims: claims,                            // Claims del usuario y dispositivo
                expires: null,                             // Sin expiración (tokens indefinidos)
                signingCredentials: credenciales);         // Credenciales de firma                          


            // ======================================================================
            // RETORNAR TOKEN COMO STRING
            // ======================================================================
            // Escribir el token como string para su uso en cookies y headers
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