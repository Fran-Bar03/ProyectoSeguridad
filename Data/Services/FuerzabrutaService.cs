using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading.Tasks.Dataflow;
using Data.Interfaces;
using Microsoft.Extensions.Logging;
using Npgsql;

namespace Data.Services
{
    /// <summary>
    /// Servicio para proteccion contra ataques de fuerza bruta usando PostgreSQL
    /// Proporciona bloqueo por email y IP con limite de 5 intentos fallidos en 15 minutos
    /// </summary>
    public class FuerzabrutaService : IFuerzabrutaService
    {
        private readonly IDatabaseService _database;
        private readonly ILogger<FuerzabrutaService> _logger;


        /// <summary>
        /// Constructor del servicio de proteccion contra fuerza bruta
        /// Inicializa las dependencias necesarias para acceder a la base de datos
        /// </summary>
        /// <param name="database">Servicio de base de datos inyectado</param>
        /// <param name="logger">Logger para registro de eventos</param>
        public FuerzabrutaService(IDatabaseService database, ILogger<FuerzabrutaService> logger)
        {
            _database = database;
            _logger = logger;
        }


        /// <summary>
        /// Verifica si un identificador (email o IP) esta bloqueado y registra el intento automaticamente
        /// Llama a la función PostgreSQL que maneja toda la logica de bloqueo y registro
        /// </summary>
        /// <param name="identificador">Identificador a verificar (email del usuario o dirección IP)</param>
        /// <param name="tipo">Tipo de identificador: "email" para usuario o "ip" para dirección</param>
        /// <returns>
        /// Tupla con:
        /// bloqueado: True si el identificador está bloqueado temporalmente
        /// intentos: Número de intentos fallidos actuales
        /// restantes: Intentos restantes antes de bloqueo (0 si ya esta bloqueado)
        /// mensaje: Mensaje descriptivo para mostrar al usuario
        /// </returns>
        public async Task<(bool bloquedo, int intentos, int restantes, string mensaje)> CheckAndRegisterAttemptAsync(string identificador, string tipo)
        {
            try
            {
                _logger.LogDebug("Verificando proteccion fuerza bruta para {Identificador} ({Tipo})", identificador, tipo);

                //Llamar a la funcion de Postgres que verifica y registra el intento
                //La funcion verifica si esta bloqueado, incrementa contador y devuelve estado
                string sqlQuery = "SELECT * FROM verificar_y_registrar_intento(@identificador, @tipo)";

                var parametros = new[]
                {
                    new NpgsqlParameter("@identificador", identificador),
                    new NpgsqlParameter("@tipo", tipo)
                };

                //Ejecutar consulta asincrona
                var resultado = await _database.ExecuteQueryAsync(sqlQuery, parametros);

                //Procesar resultados si es que existes
                if(resultado.Rows.Count > 0)
                {
                    bool bloqueado = Convert.ToBoolean(resultado.Rows[0]["esta_bloqueado"]);
                    int intentos = Convert.ToInt32(resultado.Rows[0]["intentos_actuales"]);
                    int restantes = Convert.ToInt32(resultado.Rows[0]["intentos_restantes"]);
                    string mensaje = resultado.Rows[0]["mensaje"].ToString();

                    _logger.LogInformation("Resultado verificacion fuerta bruta: Bloquedo={Bloqueado}, Intentos={Intentos}, Restantes={Restantes}", bloqueado, intentos, restantes);

                    return (bloqueado, intentos, restantes, mensaje);
                }

                //Si no hay resultado retornar valores por defectos osea no estar bloqueado
                return (false, 0, 5, "");
            }
            catch (Exception ex)
            {
                //En caso de error, por seguridad no bloquear al usuario
                //Esto evita denegacion de servicio por fallos en la BD
                _logger.LogError(ex, "Error verificando proteccion fuerza bruta para {Identificador}", identificador);
                return (false, 0, 5, "");
            }
        }


        /// <summary>
        /// Resetea los intentos fallidos para un identificador despues de un login exitoso
        /// Elimina el registro de la tabla login_intentos permitiendo nuevos intentos
        /// </summary>
        /// <param name="identificador">Identificador a resetear (email o IP)</param>
        /// <param name="tipo">Tipo de identificador: "email" o "ip"</param>
        public async Task ResetAttemptsAsync (string identificador, string tipo)
        {
            try
            {
                _logger.LogDebug("Reseteando intentos fallidos para {Identificador} ({Tipo})", identificador, tipo);


                //Llamar a la funcion de postgres que elimina el registro de intentos
                string sqlQuery = "SELECT resetear_intentos(@identificador, @tipo)";

                var parametros = new[]
                {
                    new NpgsqlParameter("@identificador", identificador),
                    new NpgsqlParameter("@tipo", tipo)
                };

                await _database.ExecuteQueryAsync(sqlQuery, parametros);
                _logger.LogInformation("Intentos fallidos resetados para {Identificador}", identificador);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error reseteando intentos fallidos para {Identificador}", identificador);
            }
        }
    }
}
