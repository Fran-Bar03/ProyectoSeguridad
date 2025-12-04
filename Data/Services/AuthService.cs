using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using BCrypt.Net;
using DTOs.Inicio;
using Microsoft.AspNetCore.SignalR.Protocol;
using Microsoft.Extensions.Logging;
using Npgsql;
using Models;
using Hasheo = BCrypt.Net;
using System.Net.Mail;
using System.Net.WebSockets;
using Data.Interfaces;

namespace Data.Services
{
    /// <summary>
    /// Servicio para manejar la autenticación y registro de usuarios de forma segura.
    /// Implementa protección contra ataques de fuerza bruta, timing attacks y proporciona
    /// mensajes de error descriptivos para el usuario final.
    /// </summary>
    public class AuthService : IAuthService
    {

        private readonly IDatabaseService _databaseService;
        private readonly ILogger<AuthService> _logger;
        private readonly IFuerzabrutaService _fuerzabrutaService;


        /// <summary>
        /// Constructor del servicio de autenticación.
        /// Inicializa las dependencias necesarias para el funcionamiento del servicio.
        /// </summary>
        /// <param name="databaseService">Servicio de base de datos inyectado</param>
        /// <param name="logger">Logger para registro de eventos</param>
        public AuthService(IDatabaseService databaseService, ILogger<AuthService> logger, IFuerzabrutaService fuerzabrutaService)
        {
            _databaseService = databaseService;
            _logger = logger;
            _fuerzabrutaService = fuerzabrutaService;
            
        }




        /// <summary>
        /// Registra un nuevo usuario en el sistema con validaciones completas
        /// Valida los datos, hashea la contraseña con BCrypt y maneja errores de forma amigable
        /// </summary>
        /// <param name="registroDto">DTO con los datos del usuario a registrar</param>
        /// <returns>Tupla indicando exito, mensaje descriptivo e ID del usuario (si aplica)</returns>
         public async Task<(bool sucess, string message, int? userId)> RegitrarUsuarioAsync(RegistrarDto registrarDto)
        {
            try
            {
                _logger.LogInformation("Intentando registrar usuario: {Email}", registrarDto.Email);

                //Generar hash seguro de la contrasena usando Bcrypt
                //Bcrypt automaticamente genera y maneja el salt, haciendo cada hash unico
                string passwordHash = Hasheo.BCrypt.HashPassword(registrarDto.Password);

                //Construccion de la llamada a la funcion postgres
                string sqlQuery = "SELECT * FROM public.insertar_usuario(" +
                    "p_nombre := @nombre," +
                    "p_apellido_paterno := @apellido_paterno," +
                    "p_apellido_materno := @apellido_materno," +
                    "p_email := @email," +
                    "p_password_hash := @password_hash)";

                var parametros = new[]
                {
                    new NpgsqlParameter("@nombre", registrarDto.Nombre),
                    new NpgsqlParameter("@apellido_paterno", registrarDto.ApellidoPaterno),
                    new NpgsqlParameter("@apellido_materno", registrarDto.ApellidoMaterno),
                    new NpgsqlParameter("@email", registrarDto.Email),
                    new NpgsqlParameter("@password_hash", passwordHash)
                };

                var (resultado, error) = await _databaseService.ExecuteFunctionWithErrorHandlingAsync(sqlQuery, parametros);

                //Si hay error en la ejecucion, retornar el mensaje
                if (!string.IsNullOrEmpty(error))
                {
                    return (false, error, null);
                }

                //Verificar si hay resultado de la funcion
                if(resultado?.Rows.Count == 0)
                {
                    return (false, "No se pudo completar el registro, intente de nuevo", null);
                }

                //Leer y procesar los resultados de la funcion
                var row = resultado.Rows[0];
                var exito = Convert.ToBoolean(row["exito"]);
                var mensaje = row["mensaje"].ToString();
                var userId = exito ? Convert.ToInt32(row["user_id"]): (int?) null;

                if (exito)
                {
                    _logger.LogInformation("Usuario resgistrado exitosamente: {Email}, ID: {UserId}", registrarDto.Email, userId);
                    return (true, mensaje, userId);
                }
                else
                {
                    _logger.LogWarning("Error en registro de usuario: {Mensaje}", mensaje);
                    return (false, mensaje, null);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,"Error inesperado registrando usuario: {Email}", registrarDto.Email);
                return (false, "Ocurrio un error durante el registro, intentelo de nuevo", null);
            }
        }


        /// <summary>
        /// Valida las credenciales de login de forma segura con proteccion persistente contra fuerza bruta
        /// Incluye verificacion por email e IP, timing attacks y manejo robusto de errores
        /// </summary>
        /// <param name="loginDto">DTO con email y contraseña para validar</param>
        /// <param name="ipAddress">Dirección IP del cliente para protección contra fuerza bruta</param>
        public async Task<(UsuarioModel usuario, string message)> ValidarLoginAsync(LoginDto loginDto, string ipAddress)
        {
            try
            {
                _logger.LogInformation("Intento de login desde IP {IpAddress} para email: {Email}",ipAddress, loginDto.Email);

                //VERIFICACION DE PROTECCION CONTRA FUERZA BRUTA POR EMAIL USANDO POSTGRE
                var (emailBloqueado, emailIntentos, emailRestantes, emailMensaje) = await _fuerzabrutaService.CheckAndRegisterAttemptAsync(loginDto.Email, "email");

                if (emailBloqueado)
                {
                    _logger.LogWarning("Email bloqueado por proteccion fuerza bruta: {Email} - {Mensaje}",loginDto.Email, emailMensaje);
                    return (null, emailMensaje);
                }


                //Llamar a al funcion de postgres para validar credenciales de forma segura
                //La funcion maneja comparacion de contrasenas con BCrypt y evita timing attacks
                string sqlQuery = "SELECT * FROM public.validar_login(" +
                    "p_email := @email," +
                    "p_password := @password)";

                var parametros = new[]
                {
                    new NpgsqlParameter("@email", loginDto.Email),
                    new NpgsqlParameter("@password", loginDto.Password)
                };

                var (resultado, error) = await _databaseService.ExecuteFunctionWithErrorHandlingAsync(sqlQuery, parametros);


                //Retornar mensaje si hay error en la ejecucion
                if (!string.IsNullOrEmpty(error))
                {
                    return (null,error);
                }

                //Verificar si hubo resultado
                if (resultado?.Rows.Count == 0)
                {
                    //El intento fallido ya fue registrado automatiamente por CheckAndRegisterAttemptAsync
                    //No es necesario llamar a  RegistroFallidoAttempt
                    await Task.Delay(2000);
                    return (null, "Error durante la validacion de credenciales");
                }

                //Procesar resultados de la funcion
                var row = resultado.Rows[0];
                var esValido = Convert.ToBoolean(row["es_valido"]);
                var mensaje = row["mensaje"].ToString();


                if (!esValido)
                {
                    //Login fallido, agrega informacion de intentos restantes
                    //Mensaje de advertencia si quedan pocos intentos

                    string advertencia = "";

                    if (emailRestantes <= 2)
                        advertencia += $" Te quedan {emailRestantes} intentos para este email";

                    if (!string.IsNullOrEmpty(advertencia))
                        mensaje += Environment.NewLine + advertencia;

                    await Task.Delay(2000);
                    return (null, mensaje);
                }


                //Si el login es exitoso, eliminar registros de intentos fallidos
                //Esto permite al usuario intentar login sin bloqueos previos
                await _fuerzabrutaService.ResetAttemptsAsync(loginDto.Email, "email");


                //Crear objeto usuario con los datos obtenidos
                var usuario = new UsuarioModel
                {
                    IdUsuario = row["user_id"] == DBNull.Value ? 0 : Convert.ToInt32(row["user_id"]),
                    Nombre = row["user_nombre"].ToString(),
                    ApellidoPaterno = row["user_apellido_paterno"].ToString(),
                    ApellidoMaterno = row["user_apellido_materno"].ToString(),
                    Email = row["user_email"].ToString(),
                };

                _logger.LogInformation("Login exitoso para usuario: {Email}", loginDto.Email);
                return (usuario, "Login exitoso");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error durante el proceso de login para: {Email}", loginDto.Email);
                return (null, "Ocurrio un error durante el proceso de login, intente nuevamente");
            }
        }



    }

}

