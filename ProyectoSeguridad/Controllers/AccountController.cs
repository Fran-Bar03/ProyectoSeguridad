using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Data.Interfaces;
using DTOs.Inicio;
using Microsoft.AspNetCore.Authorization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Data.Helpers;

namespace ProyectoSeguridad.Controllers
{
    /// <summary>
    /// Controlador para manejar las operaciones de autenticacion y gestión de cuentas de usuario
    /// Proporciona endpoints para login, registro y logout con validaciones de seguridad
    /// </summary>
    public class AccountController : Controller
    {
        private readonly IAuthService _authService;
        private readonly IJwtService _jwtService;
        private readonly ILogger<AccountController> _logger;


        /// <summary>
        /// Constructor del controlador de cuentas
        /// Inicializa los servicios necesarios mediante inyección de dependencias
        /// </summary>
        /// <param name="authService">Servicio de autenticación</param>
        /// <param name="jwtService">Servicio JWT</param>
        /// <param name="logger">Logger para registro de eventos</param>
        public AccountController (IAuthService authService, IJwtService jwtService, ILogger<AccountController> logger)
        {
            _authService= authService;
            _jwtService= jwtService;
            _logger= logger;
        }


        /// <summary>
        /// GET: /Account/Login
        /// Muestra el formulario de inicio de sesion
        /// Redirige a usuarios ya autenticados a la página principal
        /// </summary>
        /// <returns>Vista de login o redireccion a página principal</returns>
        [HttpGet]
        public IActionResult Login()
        {
            //Redirigir usuarios ya autenticados a la pagina principal
            //Evita que usuarios logueados accedan al formulario de login
            if (User.Identity.IsAuthenticated)
                return RedirectToAction("Encriptar", "Encriptacion");

            //Mostrar mensajes de redireccion del middleware si existen
            //Estos mensajes proveen contexto sobre por que se redirigio al usuario
            ModelState.Clear();
            ViewData.Clear();
            ViewBag.Message = null;

            // Mostrar mensajes de redirección del middleware si existen
            if (Request.Query.ContainsKey("message"))
            {
                string message = Request.Query["message"].FirstOrDefault();
                ViewBag.Message = message switch
                {
                    "NecesitaAutenticacion" => "Debes iniciar sesión para acceder a esta página",
                    "TokenExpirado" => "Tu sesión ha expirado, inicia sesión nuevamente",
                    "SesionInvalidaNavegador" => "La sesión no es válida en este navegador. Por seguridad, inicia sesión nuevamente.",
                    "CambioUsuarioDetectado" => "Se detectó un cambio de usuario. Por seguridad, inicia sesión nuevamente.",
                    _ => message
                };

                // Limpiar estado del modelo
                ModelState.Clear();
            }

            return View(new LoginDto());
        }

        /// <summary>
        /// POST: /Account/Login
        /// Procesa el formulario de inicio de sesion
        /// Valida credenciales, genera token JWT y establece cookie de autenticacion
        /// </summary>
        /// <param name="loginDto">DTO con datos de login</param>
        /// <returns>Redireccion a página principal o vista de login con errores</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginDto loginDto)
        {
            //Validar el modelo antes de procesar
            //Las validaciones de DataAnnotation se ejecutan automaticamente
            if (!ModelState.IsValid)
            {
                _logger.LogWarning("Intento de login con modelo invalido");
                return View(loginDto);
            }

            //Obtener la IP del cliente para proteccion contra ataques de fuerza bruta
            var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";

            //Validar credenciales con el servicio de autenticacion
            var (usuario, message) = await _authService.ValidarLoginAsync(loginDto, ipAddress);

            if (usuario != null)
            {
                //Generar token JWT para el usuario autenticado
                var token = _jwtService.GenerarJwtToken(usuario);

                //Guardar token en cookie segura con configuracion de seguridad
                Response.Cookies.Append("jwt_token", token, new CookieOptions
                {
                    HttpOnly = true,      //No accesible por JavaScript (Proteccion XSS)
                    Secure = true,       // Solo se envia por HTTPS
                    SameSite = SameSiteMode.Strict,   //Proteccion CSRF
                    Expires = DateTimeOffset.Now.AddMinutes(20)  //.Expiracion corta por seguridad
                });

                _logger.LogInformation("Login exitoso para usuario: {Email}", loginDto.Email);
                TempData["SuccessMessage"] = message;
                return RedirectToAction("Encriptar", "Encriptacion");
            }

            //Si el login falla, mostrar error en el formulario
            _logger.LogWarning("Login fallido para usuario: {Email}", loginDto.Email);

            ModelState.AddModelError("", message);
            return View(loginDto);

        }



        /// <summary>
        /// GET: /Account/Registro
        /// Muestra el formulario de registro de nuevos usuarios.
        /// </summary>
        /// <returns>Vista de registro</returns>
        [HttpGet]
        public IActionResult Registro()
        {
            //Redirigir usuarios ya autenticados
            if (User.Identity.IsAuthenticated)
                return RedirectToAction("Encriptar", "Encriptacion");

            return View();
        }


        /// <summary>
        /// POST: /Account/Registro
        /// Procesa el formulario de registro de nuevos usuarios.
        /// Valida datos, hashea contraseña y crea usuario en base de datos.
        /// </summary>
        /// <param name="registroDto">DTO con datos de registro</param>
        /// <returns>Redireccion a login o vista de registro con errores</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]    // Protección contra CSR
        public async Task<IActionResult> Registro(RegistrarDto registrarDto)
        {
            //Validar el modelo antes de procesar
            if (!ModelState.IsValid)
            {
                _logger.LogWarning("Intento de registro con modelo invalido");
                return View(registrarDto);
            }

            //Registrar usuario a traves del servicio de autenticacion
            var (sucess, message, userId) = await _authService.RegitrarUsuarioAsync(registrarDto);

            if(sucess)
            {
                _logger.LogInformation("Registro existoso por usuario: {Email}", registrarDto.Email);
                TempData["SucessMessage"] = message;
                return RedirectToAction("Login");
            }


            //Si el registro falla, mostrar error en el formulario
            _logger.LogWarning("Registro fallido para usuario: {Email}", registrarDto.Email);
            ModelState.AddModelError("", message);
            return View(registrarDto);
        }


        /// <summary>
        /// POST: /Account/Logout
        /// Cierra la sesión del usuario eliminando la cookie de autenticacion.
        /// </summary>
        /// <returns>Redireccion a pagina de login</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult LogOut()
        {

            // Headers anti-caché NUCLEARES para logout
            Response.Headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0, private";
            Response.Headers["Pragma"] = "no-cache";
            Response.Headers["Expires"] = "Mon, 01 Jan 1990 00:00:00 GMT";
            Response.Headers["Vary"] = "*";

            // Eliminar cookie de autenticacion
            Response.Cookies.Delete("jwt_token", new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict
            });

            _logger.LogInformation("Usuario cerro sesion");
            TempData["SucessMessage"] = "Sesion cerrada con exito";

            // Forzar redirección con parámetros anti-caché
            return RedirectToAction("Login", "Account", new
            {
                timestamp = DateTime.UtcNow.Ticks // Agrega timestamp único
            });
        }

        /// <summary>
        /// GET: /Account/VerToken
        /// Muestra información segura del token JWT del usuario autenticado.
        /// Solo muestra partes del token por seguridad.
        /// </summary>
        /// <returns>Vista con información del token</returns>
        public IActionResult VerToken()
        {
            try
            {
                // Obtener token de las cookies
                var token = Request.Cookies["jwt_token"];

                if (string.IsNullOrEmpty(token))
                {
                    TempData["ErrorMessage"] = "No hay token activo en las cookies.";
                    return RedirectToAction("Encriptar", "Encriptacion");
                }

                // Decodificar el token
                var handler = new JwtSecurityTokenHandler();
                var jsonToken = handler.ReadToken(token) as JwtSecurityToken;

                // Obtener información del usuario desde los claims
                var usuarioEmail = User.FindFirst(ClaimTypes.Email)?.Value;
                var usuarioNombreCompleto = User.FindFirst("NombreCompleto")?.Value;
                var usuarioId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

                // Obtener fechas del token en UTC
                DateTime fechaCreacionUtc = DateTime.UtcNow;
                DateTime fechaExpiracionUtc = DateTime.UtcNow;
                DateTime ahoraHermosillo = TimeZoneHelper.NowInHermosillo();

                // Obtener fecha de creación desde el claim "iat"
                var iatClaim = jsonToken?.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Iat);
                if (iatClaim != null && long.TryParse(iatClaim.Value, out long iatTimestamp))
                {
                    fechaCreacionUtc = DateTimeOffset.FromUnixTimeSeconds(iatTimestamp).UtcDateTime;
                }

                // Obtener fecha de expiración desde el claim "exp"
                var expClaim = jsonToken?.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Exp);
                if (expClaim != null && long.TryParse(expClaim.Value, out long expTimestamp))
                {
                    fechaExpiracionUtc = DateTimeOffset.FromUnixTimeSeconds(expTimestamp).UtcDateTime;
                }

                // Convertir a hora de Hermosillo
                var fechaCreacionHermosillo = TimeZoneHelper.ToHermosilloTime(fechaCreacionUtc);
                var fechaExpiracionHermosillo = TimeZoneHelper.ToHermosilloTime(fechaExpiracionUtc);

                // Calcular tiempo restante 
                var tiempoRestante = fechaExpiracionHermosillo - ahoraHermosillo;
                var minutosRestantes = Math.Max(0, (int)Math.Floor(tiempoRestante.TotalMinutes));
                var segundosRestantes = Math.Max(0, (int)tiempoRestante.TotalSeconds % 60);

                // Formatear fechas para mostrar
                string fechaCreacionFormateada = fechaCreacionHermosillo.ToString("yyyy.MM.dd HH:mm:ss");
                string fechaExpiracionFormateada = fechaExpiracionHermosillo.ToString("yyyy.MM.dd HH:mm:ss");

                // Crear ViewModel con información PRECISA
                var viewModel = new TokenInfoViewModel
                {
                    UsuarioEmail = usuarioEmail,
                    UsuarioNombreCompleto = usuarioNombreCompleto,
                    UsuarioId = usuarioId,
                    TokenGenerado = fechaCreacionFormateada,
                    TokenExpira = fechaExpiracionFormateada,
                    TokenGeneradoUtc = fechaCreacionUtc,
                    TokenExpiraUtc = fechaExpiracionUtc,
                    TokenGeneradoHermosillo = fechaCreacionHermosillo,
                    TokenExpiraHermosillo = fechaExpiracionHermosillo,

                    MinutosRestantes = minutosRestantes,
                    SegundosRestantes = segundosRestantes,

                    // Timestamps para JavaScript
                    ExpiraUnixTimestamp = ((DateTimeOffset)fechaExpiracionHermosillo).ToUnixTimeSeconds(),
                    GeneradoUnixTimestamp = ((DateTimeOffset)fechaCreacionHermosillo).ToUnixTimeSeconds(),

                    // Mostrar solo partes del token
                    TokenPreview = token.Length > 30 ? token.Substring(0, 30) + "..." : token,
                    TokenUltimosCaracteres = token.Length > 20 ?
                        "..." + token.Substring(token.Length - 20) : token,

                    // Claims filtrados
                    Claims = GetSafeClaims(jsonToken)
                };

                ViewBag.HideSimpleTimer = true;

                return View(viewModel);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error mostrando información del token");
                TempData["ErrorMessage"] = "Error al obtener información del token.";
                return RedirectToAction("Encriptar", "Encriptacion");
            }
        }

        private List<ClaimInfo> GetSafeClaims(JwtSecurityToken? token)
        {
            if (token == null) return new List<ClaimInfo>();

            var safeClaims = new List<ClaimInfo>();

            foreach (var claim in token.Claims)
            {
                var claimInfo = new ClaimInfo
                {
                    Tipo = claim.Type,
                    // Ocultar valores sensibles
                    Valor = IsSensitiveClaim(claim.Type) ? "*****PROTEGIDO*****" : claim.Value,
                    Descripcion = GetClaimDescription(claim.Type)
                };

                safeClaims.Add(claimInfo);
            }

            return safeClaims;
        }

        private bool IsSensitiveClaim(string claimType)
        {
            var sensitiveTypes = new[]
            {
                "UserAgentHash",
                "jti",
                JwtRegisteredClaimNames.Jti,
                "aud",
                "iss"
            };

            return sensitiveTypes.Contains(claimType);
        }

        private string GetClaimDescription(string claimType)
        {
            return claimType switch
            {
                ClaimTypes.NameIdentifier => "Identificador único del usuario en el sistema",
                ClaimTypes.Email => "Correo electrónico del usuario",
                ClaimTypes.Name => "Nombre del usuario",
                "NombreCompleto" => "Nombre completo (Nombre + Apellidos)",
                JwtRegisteredClaimNames.Jti => "Identificador único del token (JWT ID)",
                JwtRegisteredClaimNames.Exp => "Fecha de expiración del token (timestamp)",
                JwtRegisteredClaimNames.Iat => "Fecha de emisión del token (timestamp)",
                "UserAgentHash" => "Hash del navegador (protección contra uso en diferentes navegadores)",
                _ => "Información de autenticación"
            };
        }


    }
}
