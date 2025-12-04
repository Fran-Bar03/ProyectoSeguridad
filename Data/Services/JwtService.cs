using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Numerics;
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
        
        public JwtService(IConfiguration configuration, IHttpContextAccessor httpContextAccessor)
        {
            _configuration = configuration;
            _httpContextAccessor = httpContextAccessor;
        }


        /// <summary>
        /// Genera un token JWT para un usuario autenticado.
        /// Incluye claims con información del usuario y configuración de seguridad.
        /// </summary>
        /// <param name="usuario">Objeto Usuario con la información para incluir en el token</param>
        /// <returns>Token JWT firmado como string</returns>
        public string GenerarJwtToken(UsuarioModel usuario)
        {

            //Obtener Httpcontext para user-agent
            var currentUserAgentHash = UserAgentHelper.GetUserAgentHash(_httpContextAccessor.HttpContext);




            //Crear claims que se incluiran en el token
            //Los claims basicamente es informacion sobre el usuario que puede usar usado en cualquier aplicacion
            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, usuario.IdUsuario.ToString()),    //ID unico del usuario
                new Claim(ClaimTypes.Email, usuario.Email),                            //Email del usuario
                new Claim(ClaimTypes.Name, usuario.Nombre),    //Nombre completo del usuario
                new Claim("NombreCompleto", $"{usuario.Nombre} {usuario.ApellidoPaterno} {usuario.ApellidoMaterno}"),        //Claim personalizado
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),       //ID unico del token
                new Claim(JwtRegisteredClaimNames.Iat, 
                DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(),
                ClaimValueTypes.Integer64),
                new Claim("UserAgentHash",currentUserAgentHash)
            };


            //Crear clave simetrica para firmar el token usando la clave secreta de la configuracion
            var llave = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));

            //Crear credenciales de firma usando algoritmo HMAC-SHA256
            var credenciales = new SigningCredentials(llave, SecurityAlgorithms.HmacSha256);

            //Crear el token JWT con toda la configuracion necesaria
            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],       //Emisor del token
                audience: _configuration["Jwt:Audience"], //Audiencia destinataria
                claims: claims,                            //Claims del usuario
                expires: DateTime.Now.AddMinutes(Convert.ToDouble(_configuration["Jwt:ExpireMinutes"])),        //Expiracion   
                signingCredentials: credenciales);  //Credenciales de firma                          


            //Escribir el token como string para su uso
            return new JwtSecurityTokenHandler().WriteToken(token);
        }


        /// <summary>
        /// Valida un token JWT y retorna el principal de claims si es válido.
        /// Verifica la firma, emisor, audiencia y fecha de expiración del token.
        /// </summary>
        /// <param name="token">Token JWT a validar</param>
        /// <returns>ClaimsPrincipal si el token es válido, null en caso contrario</returns>
        public ClaimsPrincipal ValidarToken(string token)
        {
            try
            {

                var tokenHandler = new JwtSecurityTokenHandler();
                var llave = Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]);

                //Configurar parametros de validacion del token
                var ValidadcionParametros = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,                         // Validar la firma del token
                    IssuerSigningKey = new SymmetricSecurityKey(llave),     // Clave para validar firma
                    ValidateIssuer = true,                                  // Validar el emisor
                    ValidateAudience = true,                                // Validar la audiencia
                    ValidateLifetime = true,                                // Validar fecha de expiración
                    ValidIssuer = _configuration["Jwt:Issuer"],             // Emisor válido
                    ValidAudience = _configuration["Jwt:Audience"],         // Audiencia válida
                    ClockSkew = TimeSpan.Zero                               // Sin tolerancia para expiración
                };


                //Validar el token y retornar el principal
                return tokenHandler.ValidateToken(token, ValidadcionParametros, out _);
            }
            catch
            {
                //Si la validaicon falla, retornar null
                return null;
            }
        }
    }
}
