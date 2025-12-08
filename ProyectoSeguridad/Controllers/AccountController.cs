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
            // PROTECCIÓN AVANZADA CONTRA SCRIPTS DE ATAQUE MASIVO
            // ======================================================================
            // Obtener información del cliente para detección de patrones de ataque
            var userAgent = HttpContext.Request.Headers["User-Agent"].ToString();
            var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();

            // DETECCIÓN TEMPRANA DE PATRONES DE ATAQUE MASIVO
            // Verificar si esta petición tiene características de script automatizado
            if (DetectarPatronDeAtaqueMasivo(userAgent, ipAddress, loginDto.Email))
            {
                // Log detallado del intento de ataque
                _logger.LogWarning("INTENTO DE ATAQUE MASIVO DETECTADO - IP: {IpAddress}, UserAgent: {UserAgent}, Email: {Email}",
                    ipAddress, userAgent, loginDto.Email);

                // Aplicar retraso artificial para ralentizar scripts automatizados
                // Esto hace que los ataques masivos sean mucho más lentos y costosos
                await Task.Delay(3000); // 3 segundos de retraso

                // Mensaje genérico (no revelar información específica sobre el bloqueo)
                // Esto evita que los atacantes adapten sus scripts
                ModelState.AddModelError("", "Error de autenticación. Por favor, intenta nuevamente.");

                return View(loginDto);
            }

            // ======================================================================
            // DETECCIÓN DE DISPOSITIVO MÓVIL
            // ======================================================================
            // Obtener User-Agent para determinar tipo de dispositivo
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
                    esDispositivoMovil ? "movil" : "escritorio");
                return View(loginDto);
            }

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
                    loginDto.Email, esDispositivoMovil ? "movil" : "escritorio");

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
                loginDto.Email, esDispositivoMovil ? "movil" : "escritorio");

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


        /// <summary>
        /// Detecta patrones de ataque masivo basados en User-Agent, IP y email
        /// Específico para scripts que simulan múltiples usuarios
        /// </summary>
        private bool DetectarPatronDeAtaqueMasivo(string userAgent, string ipAddress, string email)
        {
            // 1. DETECCIÓN POR USER-AGENT
            // Verificar si el User-Agent corresponde a herramientas de automatización
            if (EsUserAgentDeScript(userAgent))
            {
                return true;
            }

            // 2. DETECCIÓN POR PATRÓN DE EMAIL
            // Scripts de ataque a menudo usan patrones predecibles en emails
            if (EsEmailDeAtaque(email))
            {
                return true;
            }

            // 3. DETECCIÓN POR IP
            // Verificar si la IP proviene de rangos conocidos de hosting/VPS
            // (los atacantes a menudo usan servidores cloud para ataques)
            if (EsIPDeHosting(ipAddress))
            {
                return true;
            }

            // 4. DETECCIÓN POR PATRONES CONJUNTOS
            // Combinaciones específicas que indican ataque automatizado

            // User-Agent muy corto + email con números secuenciales
            if (userAgent.Length < 15 && ContieneNumerosSecuenciales(email))
            {
                return true;
            }

            return false;
        }

        /// <summary>
        /// Detecta patrones de registro automatizado
        /// </summary>
        private bool DetectarPatronRegistroAutomatizado(string userAgent, string ipAddress, string email, string nombre)
        {
            // 1. Nombres genéricos o secuenciales
            var nombresGenericos = new[] { "test", "user", "admin", "demo", "guest" };
            if (nombresGenericos.Any(n => nombre.ToLower().Contains(n)))
            {
                return true;
            }

            // 2. Emails con patrones de ataque
            if (EsEmailDeAtaque(email))
            {
                return true;
            }

            // 3. Múltiples registros desde misma IP en poco tiempo
            // (Esto requeriría tracking en cache/sesión, implementación básica)

            return false;
        }

        /// <summary>
        /// Verifica si un email tiene características de ataque automatizado
        /// </summary>
        private bool EsEmailDeAtaque(string email)
        {
            if (string.IsNullOrEmpty(email))
                return false;

            var emailLower = email.ToLower();

            // Patrones comunes en emails de scripts de ataque
            var patronesAtaque = new[]
            {
                // Emails de prueba/secuenciales
                @"^test\d*@", @"^user\d*@", @"^admin\d*@",
                @"^demo\d*@", @"^guest\d*@",
                
                // Solo números
                @"^\d+@",
                
                // Dominios de prueba
                @"@example\.com$", @"@test\.com$", @"@demo\.com$",
                @"@fake\.com$", @"@dummy\.com$",
                
                // Patrones secuenciales
                @"\d{3,}@", // Muchos números al inicio
                @"@\d+\.\d+" // IP como dominio
            };

            foreach (var patron in patronesAtaque)
            {
                if (System.Text.RegularExpressions.Regex.IsMatch(emailLower, patron))
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Verifica si una IP pertenece a rangos de hosting/VPS
        /// </summary>
        private bool EsIPDeHosting(string ipAddress)
        {
            if (string.IsNullOrEmpty(ipAddress))
                return false;

            // Rangos de IPs comunes en servicios cloud/VPS
            var rangosHosting = new[]
            {
                "192.0.2.", // TEST-NET (usado en ejemplos)
                "198.51.100.", // TEST-NET-2
                "203.0.113.", // TEST-NET-3
                "10.", // Redes privadas
                "172.16.", "172.17.", "172.18.", "172.19.",
                "172.20.", "172.21.", "172.22.", "172.23.",
                "172.24.", "172.25.", "172.26.", "172.27.",
                "172.28.", "172.29.", "172.30.", "172.31.",
                "192.168.", // Redes privadas
                "100.64.", "100.65.", "100.66.", "100.67.", // CG-NAT
                "100.68.", "100.69.", "100.70.", "100.71.",
                "169.254.", // Link-local
                
                // Algunos rangos de proveedores cloud (ejemplos)
                "34.", "35.", "104.", "108.", "130.", "140.",
                "142.", "144.", "146.", "148.", "150.", "152.",
                "154.", "156.", "158.", "160.", "162.", "164.",
                "185.", "188.", "192.", "194.", "195.", "198.",
                "200.", "202.", "204.", "206.", "208.", "210."
            };

            return rangosHosting.Any(rango => ipAddress.StartsWith(rango));
        }

        /// <summary>
        /// Verifica si un string contiene números secuenciales
        /// </summary>
        private bool ContieneNumerosSecuenciales(string input)
        {
            if (string.IsNullOrEmpty(input))
                return false;

            // Buscar patrones como user1, user2, user3, etc.
            var match = System.Text.RegularExpressions.Regex.Match(input, @"(\d{2,})");
            if (match.Success)
            {
                // Verificar si el número es "redondo" o secuencial típico
                var numero = match.Value;
                if (numero.All(char.IsDigit))
                {
                    int num;
                    if (int.TryParse(numero, out num))
                    {
                        // Números como 01, 02, 03 o 001, 002, 003
                        if (num <= 100 && numero.Length >= 2)
                            return true;

                        // Números redondos (10, 20, 30, etc.)
                        if (num % 10 == 0 && num <= 1000)
                            return true;
                    }
                }
            }

            return false;
        }

        /// <summary>
        /// Detecta si el User-Agent corresponde a un script automatizado
        /// Versión simplificada de la función en Program.cs
        /// </summary>
        private bool EsUserAgentDeScript(string userAgent)
        {
            if (string.IsNullOrEmpty(userAgent))
                return true; // Sin User-Agent = sospechoso

            var userAgentLower = userAgent.ToLower();

            // ======================================================================
            // PERMITIR NAVEGADORES COMUNES (INCLUYENDO LOCALHOST)
            // ======================================================================
            var navegadoresPermitidos = new[]
            {
        // Firefox y derivados
        "mozilla", "firefox", "gecko",
        
        // Chrome/Chromium y derivados
        "chrome", "chromium", "crios", "brave", "vivaldi",
        "edge", "edg", "opera", "opr", "safari",
        
        // Safari y WebKit
        "safari", "webkit", "applewebkit",
        
        // Internet Explorer
        "msie", "trident",
        
        // Móviles
        "mobile", "android", "iphone", "ipad",
        
        // Testing local
        "postmanruntime", "insomnia", "thunder client",
        "swagger", "openapi"
    };

            // Si es un navegador conocido, NO es script
            foreach (var navegador in navegadoresPermitidos)
            {
                if (userAgentLower.Contains(navegador))
                {
                    return false; // NO es script
                }
            }

            // ======================================================================
            // SOLO BLOQUEAR HERRAMIENTAS DE ATAQUE REALES
            // ======================================================================
            var herramientasAtaque = new[]
            {
        // Herramientas de hacking específicas
        "sqlmap", "nikto", "hydra", "medusa", "patator",
        "brutus", "dirb", "gobuster", "ffuf", "wfuzz",
        "arjun", "xsstrike", "commix", "wapiti",
        
        // Network scanners maliciosos
        "masscan", "zmap", "unicornscan",
        
        // Fuerza bruta específica
        "john the ripper", "hashcat", "rainbowcrack",
        
        // Scripts personalizados maliciosos
        "attackbot", "hackbot", "exploit",
        "vulnerability scanner", "security scanner",
        
        // Muy sospechosos
        @"^\d+\.\d+\.\d+\.\d+$", // Solo IP
        @"^.{1,5}$", // Muy corto
        @"<script", "javascript:", "onload=", // Inyección
    };

            foreach (var herramienta in herramientasAtaque)
            {
                if (System.Text.RegularExpressions.Regex.IsMatch(userAgentLower, herramienta))
                {
                    return true;
                }
            }

            // ======================================================================
            // POR DEFECTO: PERMITIR (mejor permitir falso negativo que bloquear usuario)
            // ======================================================================
            return false;
        }

        /// <summary>
        /// Detecta si el User-Agent corresponde a un dispositivo móvil o tablet
        /// </summary>
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


