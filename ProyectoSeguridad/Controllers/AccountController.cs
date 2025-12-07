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
    /// MODIFICADO: Ahora incluye detección y manejo de dispositivos móviles
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
        public AccountController(IAuthService authService, IJwtService jwtService, ILogger<AccountController> logger)
        {
            _authService = authService;
            _jwtService = jwtService;
            _logger = logger;
        }


        /// <summary>
        /// GET: /Account/Login
        /// Muestra el formulario de inicio de sesion
        /// Redirige a usuarios ya autenticados a la página principal
        /// MODIFICADO: Ahora detecta dispositivos móviles y ajusta la experiencia
        /// </summary>
        /// <returns>Vista de login o redireccion a página principal</returns>
        [HttpGet]
        public IActionResult Login()
        {
            // ======================================================================
            // DETECCIÓN DE DISPOSITIVO MÓVIL
            // ======================================================================
            // Obtener User-Agent para determinar tipo de dispositivo
            var userAgent = HttpContext.Request.Headers["User-Agent"].ToString();
            var esDispositivoMovil = EsDispositivoMovil(userAgent);

            // Guardar información en ViewBag para uso en la vista
            ViewBag.EsDispositivoMovil = esDispositivoMovil;
            ViewBag.UserAgent = userAgent;

            // ======================================================================
            // REDIRECCIÓN PARA USUARIOS YA AUTENTICADOS
            // ======================================================================
            // Redirigir usuarios ya autenticados a la pagina principal
            // Evita que usuarios logueados accedan al formulario de login
            if (User.Identity.IsAuthenticated)
            {
                var redirectUrl = "/Encriptacion/Encriptar";
                if (esDispositivoMovil)
                {
                    redirectUrl += "?dispositivo=mobile"; // Agregar parámetro para móviles
                }
                return Redirect(redirectUrl);
            }

            // ======================================================================
            // MANEJO DE MENSAJES DE REDIRECCIÓN
            // ======================================================================
            // Mostrar mensajes de redireccion del middleware si existen
            // Estos mensajes proveen contexto sobre por que se redirigio al usuario
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
                    "TokenInvalido" => "Token invalido. Inicia sesion de nuevo",
                    "SesionInvalidaNavegador" => "La sesión no es válida en este navegador. Por seguridad, inicia sesión nuevamente.",
                    "CambioUsuarioDetectado" => "Se detectó un cambio de usuario. Por seguridad, inicia sesión nuevamente.",
                    _ => message
                };

                // Limpiar estado del modelo
                ModelState.Clear();
            }

            // ======================================================================
            // PARÁMETRO ESPECÍFICO PARA MÓVILES
            // ======================================================================
            // Si viene con parámetro de dispositivo móvil, guardarlo
            if (Request.Query.ContainsKey("dispositivo") && Request.Query["dispositivo"] == "mobile")
            {
                ViewBag.Dispositivo = "mobile";
            }

            return View(new LoginDto());
        }

        /// <summary>
        /// POST: /Account/Login
        /// Procesa el formulario de inicio de sesion
        /// Valida credenciales, genera token JWT y establece cookie de autenticacion
        /// MODIFICADO: Ahora configura cookies específicas para dispositivos móviles
        /// </summary>
        /// <param name="loginDto">DTO con datos de login</param>
        /// <returns>Redireccion a página principal o vista de login con errores</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginDto loginDto)
        {
            // ======================================================================
            // DETECCIÓN DE DISPOSITIVO MÓVIL
            // ======================================================================
            // Obtener User-Agent para determinar tipo de dispositivo
            var userAgent = HttpContext.Request.Headers["User-Agent"].ToString();
            var esDispositivoMovil = EsDispositivoMovil(userAgent);

            // Guardar información en ViewBag para uso en la vista si hay errores
            ViewBag.EsDispositivoMovil = esDispositivoMovil;

            // ======================================================================
            // VALIDACIÓN DEL MODELO
            // ======================================================================
            // Validar el modelo antes de procesar
            // Las validaciones de DataAnnotation se ejecutan automaticamente
            if (!ModelState.IsValid)
            {
                _logger.LogWarning("Intento de login con modelo invalido desde dispositivo: {Dispositivo}",
                    esDispositivoMovil ? "móvil" : "escritorio");
                return View(loginDto);
            }

            // ======================================================================
            // OBTENER INFORMACIÓN DEL CLIENTE
            // ======================================================================
            // Obtener la IP del cliente para proteccion contra ataques de fuerza bruta
            var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";

            // ======================================================================
            // VALIDAR CREDENCIALES
            // ======================================================================
            // Validar credenciales con el servicio de autenticacion
            var (usuario, message) = await _authService.ValidarLoginAsync(loginDto, ipAddress);

            if (usuario != null)
            {
                // ======================================================================
                // GENERAR TOKEN JWT
                // ======================================================================
                // Generar token JWT para el usuario autenticado
                // El token ahora incluye información del dispositivo
                var token = _jwtService.GenerarJwtToken(usuario);

                // ======================================================================
                // CONFIGURAR COOKIE SEGURA
                // ======================================================================
                // Configurar opciones de cookie según tipo de dispositivo
                var cookieOptions = new CookieOptions
                {
                    HttpOnly = true,      // No accesible por JavaScript (Proteccion XSS)
                    Secure = true,        // Solo se envia por HTTPS
                    SameSite = SameSiteMode.Lax, // Balance entre seguridad y compatibilidad
                    Expires = DateTimeOffset.Now.AddDays(30),
                    MaxAge = TimeSpan.FromDays(30)
                };

                // ======================================================================
                // AJUSTES ESPECÍFICOS PARA DISPOSITIVOS MÓVILES
                // ======================================================================
                // Para móviles, algunos navegadores requieren SameSite=None
                // para que las cookies funcionen correctamente en apps web progresivas
                if (esDispositivoMovil)
                {
                    cookieOptions.SameSite = SameSiteMode.None;
                }

                // ======================================================================
                // ESTABLECER COOKIE
                // ======================================================================
                // Guardar token en cookie segura con configuracion de seguridad
                Response.Cookies.Append("jwt_token", token, cookieOptions);

                // ======================================================================
                // LOG Y REDIRECCIÓN
                // ======================================================================
                _logger.LogInformation("Login exitoso para usuario: {Email} desde dispositivo: {Dispositivo}",
                    loginDto.Email, esDispositivoMovil ? "móvil" : "escritorio");

                TempData["SuccessMessage"] = message;

                // Redirigir con parámetro de dispositivo si es móvil
                var redirectUrl = "/Encriptacion/Encriptar";
                if (esDispositivoMovil)
                {
                    redirectUrl += "?dispositivo=mobile";
                }
                return Redirect(redirectUrl);
            }

            // ======================================================================
            // MANEJO DE LOGIN FALLIDO
            // ======================================================================
            // Si el login falla, mostrar error en el formulario
            _logger.LogWarning("Login fallido para usuario: {Email} desde dispositivo: {Dispositivo}",
                loginDto.Email, esDispositivoMovil ? "móvil" : "escritorio");

            ModelState.AddModelError("", message);
            return View(loginDto);

        }



        /// <summary>
        /// GET: /Account/Registro
        /// Muestra el formulario de registro de nuevos usuarios.
        /// MODIFICADO: Detecta dispositivos móviles para optimizar la experiencia
        /// </summary>
        /// <returns>Vista de registro</returns>
        [HttpGet]
        public IActionResult Registro()
        {
            // ======================================================================
            // DETECCIÓN DE DISPOSITIVO MÓVIL
            // ======================================================================
            // Obtener User-Agent para determinar tipo de dispositivo
            var userAgent = HttpContext.Request.Headers["User-Agent"].ToString();
            var esDispositivoMovil = EsDispositivoMovil(userAgent);

            // Guardar información en ViewBag
            ViewBag.EsDispositivoMovil = esDispositivoMovil;

            // ======================================================================
            // REDIRECCIÓN PARA USUARIOS YA AUTENTICADOS
            // ======================================================================
            // Redirigir usuarios ya autenticados
            if (User.Identity.IsAuthenticated)
            {
                var redirectUrl = "/Encriptacion/Encriptar";
                if (esDispositivoMovil)
                {
                    redirectUrl += "?dispositivo=mobile";
                }
                return Redirect(redirectUrl);
            }

            return View();
        }


        /// <summary>
        /// POST: /Account/Registro
        /// Procesa el formulario de registro de nuevos usuarios.
        /// Valida datos, hashea contraseña y crea usuario en base de datos.
        /// MODIFICADO: Incluye información del dispositivo en los logs
        /// </summary>
        /// <param name="registroDto">DTO con datos de registro</param>
        /// <returns>Redireccion a login o vista de registro con errores</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]    // Protección contra CSRF
        public async Task<IActionResult> Registro(RegistrarDto registrarDto)
        {
            // ======================================================================
            // DETECCIÓN DE DISPOSITIVO MÓVIL
            // ======================================================================
            // Obtener User-Agent para determinar tipo de dispositivo
            var userAgent = HttpContext.Request.Headers["User-Agent"].ToString();
            var esDispositivoMovil = EsDispositivoMovil(userAgent);

            // Guardar información en ViewBag
            ViewBag.EsDispositivoMovil = esDispositivoMovil;

            // ======================================================================
            // VALIDACIÓN DEL MODELO
            // ======================================================================
            // Validar el modelo antes de procesar
            if (!ModelState.IsValid)
            {
                _logger.LogWarning("Intento de registro con modelo invalido desde dispositivo: {Dispositivo}",
                    esDispositivoMovil ? "móvil" : "escritorio");
                return View(registrarDto);
            }

            // ======================================================================
            // REGISTRAR USUARIO
            // ======================================================================
            // Registrar usuario a traves del servicio de autenticacion
            var (sucess, message, userId) = await _authService.RegitrarUsuarioAsync(registrarDto);

            if (sucess)
            {
                _logger.LogInformation("Registro existoso por usuario: {Email} desde dispositivo: {Dispositivo}",
                    registrarDto.Email, esDispositivoMovil ? "móvil" : "escritorio");

                TempData["SucessMessage"] = message;
                return RedirectToAction("Login");
            }


            // ======================================================================
            // MANEJO DE REGISTRO FALLIDO
            // ======================================================================
            // Si el registro falla, mostrar error en el formulario
            _logger.LogWarning("Registro fallido para usuario: {Email} desde dispositivo: {Dispositivo}",
                registrarDto.Email, esDispositivoMovil ? "móvil" : "escritorio");

            ModelState.AddModelError("", message);
            return View(registrarDto);
        }


        /// <summary>
        /// POST: /Account/Logout
        /// Cierra la sesión del usuario eliminando la cookie de autenticacion.
        /// MODIFICADO: Maneja dispositivos móviles en la redirección
        /// </summary>
        /// <returns>Redireccion a pagina de login</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult LogOut()
        {
            // ======================================================================
            // DETECCIÓN DE DISPOSITIVO MÓVIL
            // ======================================================================
            // Obtener User-Agent para determinar tipo de dispositivo
            var userAgent = HttpContext.Request.Headers["User-Agent"].ToString();
            var esDispositivoMovil = EsDispositivoMovil(userAgent);

            // ======================================================================
            // ELIMINAR COOKIE DE AUTENTICACIÓN
            // ======================================================================
            // Eliminar cookie de autenticacion
            Response.Cookies.Delete("jwt_token", new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Lax
            });

            // ======================================================================
            // LOG Y REDIRECCIÓN
            // ======================================================================
            _logger.LogInformation("Usuario cerró sesión desde dispositivo: {Dispositivo}",
                esDispositivoMovil ? "móvil" : "escritorio");

            TempData["SuccessMessage"] = "Sesion cerrada con exito";

            // ======================================================================
            // REDIRECCIÓN CON PARÁMETROS ANTI-CACHÉ
            // ======================================================================
            // Redirigir con parámetro de dispositivo si es móvil
            var redirectUrl = "/Account/Login";
            if (esDispositivoMovil)
            {
                redirectUrl += "?dispositivo=mobile";
            }

            // Forzar redirección con parámetros anti-caché
            return Redirect(redirectUrl);
        }

        /// <summary>
        /// GET: /Account/VerToken
        /// Muestra información segura del token JWT del usuario autenticado.
        /// Solo muestra partes del token por seguridad.
        /// MODIFICADO: Muestra información del dispositivo en la vista
        /// </summary>
        /// <returns>Vista con información del token</returns>
        public IActionResult VerToken()
        {
            try
            {
                // ======================================================================
                // DETECCIÓN DE DISPOSITIVO MÓVIL
                // ======================================================================
                // Obtener User-Agent para determinar tipo de dispositivo
                var userAgent = HttpContext.Request.Headers["User-Agent"].ToString();
                var esDispositivoMovil = EsDispositivoMovil(userAgent);

                // Guardar información en ViewBag
                ViewBag.EsDispositivoMovil = esDispositivoMovil;

                // ======================================================================
                // OBTENER TOKEN DE LAS COOKIES
                // ======================================================================
                // Obtener token de las cookies
                var token = Request.Cookies["jwt_token"];

                if (string.IsNullOrEmpty(token))
                {
                    TempData["ErrorMessage"] = "No hay token activo en las cookies.";

                    // Redirigir con parámetro de dispositivo
                    var redirectUrl = "/Encriptacion/Encriptar";
                    if (esDispositivoMovil)
                    {
                        redirectUrl += "?dispositivo=mobile";
                    }
                    return Redirect(redirectUrl);
                }

                // ======================================================================
                // DECODIFICAR EL TOKEN
                // ======================================================================
                // Decodificar el token para extraer información
                var handler = new JwtSecurityTokenHandler();
                var jsonToken = handler.ReadToken(token) as JwtSecurityToken;

                // ======================================================================
                // OBTENER INFORMACIÓN DEL USUARIO
                // ======================================================================
                // Obtener información del usuario desde los claims
                var usuarioEmail = User.FindFirst(ClaimTypes.Email)?.Value;
                var usuarioNombreCompleto = User.FindFirst("NombreCompleto")?.Value;
                var usuarioId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

                // ======================================================================
                // OBTENER INFORMACIÓN DEL DISPOSITIVO DESDE EL TOKEN
                // ======================================================================
                // Obtener información del dispositivo almacenada en el token
                var dispositivoClaim = jsonToken?.Claims.FirstOrDefault(c => c.Type == "Dispositivo");
                var userAgentHashClaim = jsonToken?.Claims.FirstOrDefault(c => c.Type == "UserAgentHash");

                var dispositivo = dispositivoClaim?.Value ?? "desktop";
                var userAgentHash = userAgentHashClaim?.Value ?? "";

                // ======================================================================
                // OBTENER FECHAS DEL TOKEN
                // ======================================================================
                // Obtener fecha de creación desde el claim "iat"
                DateTime fechaCreacionUtc = DateTime.UtcNow;
                var iatClaim = jsonToken?.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Iat);

                if (iatClaim != null && long.TryParse(iatClaim.Value, out long iatTimestamp))
                {
                    fechaCreacionUtc = DateTimeOffset.FromUnixTimeSeconds(iatTimestamp).UtcDateTime;
                }

                // Convertir a hora de Hermosillo
                var fechaCreacionHermosillo = TimeZoneHelper.ToHermosilloTime(fechaCreacionUtc);

                // Formatear fecha para mostrar
                string fechaCreacionFormateada = fechaCreacionHermosillo.ToString("yyyy.MM.dd HH:mm:ss");


                // ======================================================================
                // CREAR VIEWMODEL CON INFORMACIÓN COMPLETA
                // ======================================================================
                var viewModel = new TokenInfoViewModel
                {
                    UsuarioEmail = usuarioEmail,
                    UsuarioNombreCompleto = usuarioNombreCompleto,
                    UsuarioId = usuarioId,
                    TokenGenerado = fechaCreacionFormateada,
                    TokenExpira = "No expira",
                    TokenGeneradoUtc = fechaCreacionUtc,
                    TokenGeneradoHermosillo = fechaCreacionHermosillo,

                    // Claims filtrados
                    Claims = GetSafeClaims(jsonToken),

                    // Mostrar solo partes del token
                    TokenPreview = token.Length > 30 ? token.Substring(0, 30) + "..." : token,
                    TokenUltimosCaracteres = token.Length > 20 ?
                        "..." + token.Substring(token.Length - 20) : token,

                    // Información adicional para mostrar
                    Dispositivo = dispositivo,
                    UserAgentHashPreview = userAgentHash.Length > 10 ?
                        userAgentHash.Substring(0, 10) + "..." : userAgentHash
                };

                // Configurar ViewBag
                ViewBag.HideSimpleTimer = true;
                ViewBag.DispositivoActual = esDispositivoMovil ? "móvil/tablet" : "escritorio";
                ViewBag.DispositivoToken = dispositivo == "mobile" ? "móvil/tablet" : "escritorio";

                return View(viewModel);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error mostrando información del token");
                TempData["ErrorMessage"] = "Error al obtener información del token.";

                // Redirigir con parámetro de dispositivo
                var userAgent = HttpContext.Request.Headers["User-Agent"].ToString();
                var esDispositivoMovil = EsDispositivoMovil(userAgent);

                var redirectUrl = "/Encriptacion/Encriptar";
                if (esDispositivoMovil)
                {
                    redirectUrl += "?dispositivo=mobile";
                }
                return Redirect(redirectUrl);
            }
        }

        // ======================================================================
        // MÉTODOS PRIVADOS AUXILIARES
        // ======================================================================

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
                JwtRegisteredClaimNames.Iat => "Fecha de emisión del token (timestamp)",
                "UserAgentHash" => "Hash del navegador (protección contra uso en diferentes navegadores)",
                "Dispositivo" => "Tipo de dispositivo donde se creó el token (mobile/desktop)",
                _ => "Información de autenticación"
            };
        }

        // ======================================================================
        // FUNCIÓN PARA DETECTAR DISPOSITIVOS MÓVILES
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