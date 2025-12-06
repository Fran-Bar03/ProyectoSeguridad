using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Data.Interfaces;
using DTOs.Encryption;
using System.Security.Claims;


namespace ProyectoSeguridad.Controllers
{
    /// <summary>
    /// Controlador para operaciones de encriptacion y desencriptacion de mensajes
    /// Todas las acciones requieren autenticacion previa mediante JWT
    /// </summary>
         // Atributo que requiere autenticacion para todas las acciones del controlador
    public class EncriptacionController : Controller
    {
        private readonly IEncryptionService _encryptionService;
        private readonly ILogger<EncriptacionController> _logger;


        /// <summary>
        /// Constructor del controlador de encriptacion
        /// </summary>
        /// <param name="encryptionService">Servicio de encriptacion inyectado</param>
        /// <param name="logger">Logger para registro de operaciones</param>
        public EncriptacionController(IEncryptionService encryptionService, ILogger<EncriptacionController> logger)
        {
            _encryptionService = encryptionService;
            _logger = logger;
        }


        /// <summary>
        /// GET: /Encriptacion/Encriptar
        /// Muestra el formulario para encriptar mensajes.
        /// Incluye información del usuario actual en la vista.
        /// </summary>
        /// <returns>Vista de encriptación</returns>
        [HttpGet]
        public IActionResult Encriptar()
        {
            HttpContext.Response.Headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0, private";
            HttpContext.Response.Headers["Pragma"] = "no-cache";
            HttpContext.Response.Headers["Expires"] = "Mon, 01 Jan 1990 00:00:00 GMT";
            HttpContext.Response.Headers["Vary"] = "*";

            // ===== NUEVO: LIMPIAR ESTADO COMPLETAMENTE =====
            ModelState.Clear();
            ViewData.Clear();
            TempData.Clear();

            // Siempre retornar un nuevo modelo vacío
            return View(new EncriptarDto());
        }


        /// <summary>
        /// POST: /Encriptacion/Encriptar
        /// Procesa el formulario de encriptacion de mensajes.
        /// Usa AES-256 para encriptar el mensaje y genera una llave única.
        /// </summary>
        /// <param name="encriptarDto">DTO con el mensaje a encriptar</param>
        /// <returns>Vista con el mensaje encriptado y la llave generada</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]    //Proteccion contra CSRF
        public IActionResult Encriptar(EncriptarDto encriptarDto)
        {
            HttpContext.Response.Headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0, private";
            HttpContext.Response.Headers["Pragma"] = "no-cache";
            HttpContext.Response.Headers["Expires"] = "0";

            if (!ModelState.IsValid)
            {
                // Limpiar completamente en caso de error
                encriptarDto.MensajeEncriptado = null;
                encriptarDto.Llave = null;
                ModelState.Clear();

                return View(new EncriptarDto());
            }

            try
            {
                // Encriptar el mensaje usando el servicio de encriptacion
                var (mensajeEncriptado, llave) = _encryptionService.EncriptarAES(encriptarDto.Mensaje);

                //  Crear NUEVO objeto, no reusar
                var resultadoDto = new EncriptarDto
                {
                    MensajeEncriptado = mensajeEncriptado,
                    Llave = llave
                   
                };

                // Mostrar mensaje de éxito en la vista
                ViewBag.Success = "Mensaje encriptado con éxito";

                // Mantener la información del usuario en la vista
                ViewBag.UsuarioNombre = User.FindFirst("NombreCompleto")?.Value ?? User.Identity.Name;

                // Headers anti-caché
                HttpContext.Response.Headers["Cache-Control"] = "no-cache, no-store, must-revalidate";

                return View(resultadoDto);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error durante encriptacion para el usuario: {Usuario}", User.Identity.Name);
                ModelState.AddModelError("", ex.Message);
                ViewBag.UsuarioNombre = User.FindFirst("NombreCompleto")?.Value ?? User.Identity.Name;

                // Retornar DTO limpio
                return View(new EncriptarDto());
            }
        }


        /// <summary>
        /// GET: /Encriptacion/Desencriptar
        /// Muestra el formulario para desencriptar mensajes
        /// </summary>
        /// <returns>Vista de desencriptacion</returns>
        [HttpGet]
        public IActionResult Desencriptar()
        {

            ModelState.Clear();
            ViewData.Clear();
            //Obtener informacion del usuario para msotrar en la vista
            ViewBag.UsuarioNombre = User.FindFirst("NombreCompleto")?.Value ?? User.Identity.Name;
            ViewBag.UsuarioEmail = User.FindFirst(ClaimTypes.Email)?.Value;

            HttpContext.Response.Headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0";
            HttpContext.Response.Headers["Pragma"] = "no-cache";

            // Siempre retornar nuevo modelo
            return View(new DesencriptarDto());

        }



        /// <summary>
        /// POST: /Encriptacion/Desencriptar
        /// Procesa el formulario de desencriptacion de mensajes
        /// Usa AES-256 con la llave proporcionada para desencriptar el mensaje
        /// </summary>
        /// <param name="desencriptarDto">DTO con mensaje encriptado y llave</param>
        /// <returns>Vista con el mensaje desencriptado o errores</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]     //Proteccion CSRF
        public IActionResult Desencriptar(DesencriptarDto desencriptarDto)
        {
            if (!ModelState.IsValid)
            {
                // Limpiar resultados previos
                desencriptarDto.MensajeOriginal = null;
                desencriptarDto.Exito = false;

                ViewBag.UsuarioNombre = User.FindFirst("NombreCompleto")?.Value ?? User.Identity.Name;

                // Headers anti-caché
                HttpContext.Response.Headers["Cache-Control"] = "no-cache, no-store, must-revalidate";

                return View(desencriptarDto);
            }

            try
            {
                desencriptarDto.MensajeOriginal = _encryptionService.DesencriptarAES(
                    desencriptarDto.MensajeEncriptado,
                    desencriptarDto.Llave
                );
                desencriptarDto.Exito = true;
                ViewBag.Success = "Mensaje desencriptado con éxito";
            }
            catch (Exception ex)
            {
                desencriptarDto.Exito = false;
                _logger.LogError(ex, "Error durante desencriptacion para usuario: {Usuario}", User.Identity.Name);
                ModelState.AddModelError("", ex.Message);
            }

            ViewBag.UsuarioNombre = User.FindFirst("NombreCompleto")?.Value ?? User.Identity.Name;

            // ===== NUEVO: Headers anti-caché =====
            HttpContext.Response.Headers["Cache-Control"] = "no-cache, no-store, must-revalidate";

            return View(desencriptarDto);
        }
    }
}
