using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Data.Interfaces;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Npgsql;

namespace Data.Services
{
    /// <summary>
    /// Servicio singleton para manejar todas las operaciones de base de datos PostgreSQL.
    /// Implementa el patrón Singleton para asegurar una única instancia y conexión eficiente.
    /// Proporciona métodos seguros para ejecutar consultas y funciones con manejo robusto de errores. 
    /// </summary>
    public class DatabaseService : IDatabaseService
    {
        private readonly string _connectionString;
        private readonly ILogger<DatabaseService> _logger;





        /// <summary>
        /// Constructor privado para prevenir la instanciación directa fuera de la clase.
        /// Inicializa la cadena de conexión y el logger para el servicio.
        /// </summary>
        /// <param name="configuration">Instancia de IConfiguration para obtener la cadena de conexión</param>
        /// <param name="logger">Instancia de ILogger para registro de eventos</param>

        public DatabaseService(IConfiguration configuration, ILogger<DatabaseService> logger)
        {

            _logger = logger;

            // ==============================================
            // ORDEN DE PRIORIDAD PARA CONEXIÓN A BD:
            // ==============================================
            //  Railway (Variables de entorno) DESPLIEGUE
            _connectionString = Environment.GetEnvironmentVariable("CONNECTION_STRING");

            // Local (secrets.json)  DESARROLLO
            if (string.IsNullOrEmpty(_connectionString))
            {
                _connectionString = configuration.GetConnectionString("CONNECTION_STRING") ??
                                   configuration["ConnectionStrings:CONNECTION_STRING"];
            }

            // Verificar que se configuró algo
            if (string.IsNullOrEmpty(_connectionString))
            {
                throw new Exception(
                    "ERROR: Cadena de conexión no configurada.\n\n" +
                    "PARA RAILWAY:\n" +
                    "1. Ve a Railway Dashboard → Variables\n" +
                    "2. Añade: CONNECTION_STRING = [tu_cadena]\n\n" +
                    "PARA LOCAL:\n" +
                    "1. Asegúrate de tener secrets.json\n" +
                    "2. Con: {\"ConnectionStrings\":{\"CONNECTION_STRING\":\"[tu_cadena]\"}}"
                );
            }

            // Debug: mostrar qué se usó
            var source = Environment.GetEnvironmentVariable("CONNECTION_STRING") != null
                ? "Railway (Variables)"
                : "Local (secrets.json)";

            Console.WriteLine($"✓ DatabaseService configurado desde: {source}");
        }




        /// <summary>
        /// Ejecuta una consulta SQL de forma asíncrona y segura contra la base de datos PostgreSQL.
        /// Utiliza parámetros para prevenir ataques de SQL injection y maneja diferentes tipos de errores.
        /// </summary>
        /// <param name="query">Consulta SQL o llamada a función a ejecutar</param>
        /// <param name="parametros">Parámetros opcionales para la consulta (protección SQL injection)</param>
        /// <returns>DataTable con los resultados de la consulta</returns>
        /// <exception cref="Exception">Excepción con mensaje amigable según el tipo de error</exception>
        public async Task<DataTable> ExecuteQueryAsync(string query, params NpgsqlParameter[] parametros)
        {
            NpgsqlConnection connection = null;
            try
            {
                //Crear Datatable para almacenar los resultados de la consulta
                var dataTable = new DataTable();


                //Crear y abrir conexion a la base de datos
                connection = new NpgsqlConnection(_connectionString);
                await connection.OpenAsync();

                //Crear comando SQL con los parametros proporcionados
                using var comando = new NpgsqlCommand(query, connection);
                comando.Parameters.AddRange(parametros);

                //Ejecutar consulta y cargar resultados en el DataTable
                using var reader = await comando.ExecuteReaderAsync();
                dataTable.Load(reader);

                return dataTable;
            }

            // Manejo específico de errores de PostgreSQL con mensajes amigables para el usuario
            catch (PostgresException ex) when (ex.SqlState == "23505") // Violacion de unicidad
            {
                _logger.LogWarning(ex, "Intento de duplicado en base de datos: {MessageText}", ex.MessageText);
                throw new Exception("El correo electrónico ya está registrado en el sistema");
            }
            catch (PostgresException ex) when (ex.SqlState == "23502") // Violacion de campo no nulo
            {
                _logger.LogWarning(ex, "Violación de campo nulo: {MessageText}", ex.MessageText);
                throw new Exception("Faltan campos obligatorios para completar la operación");
            }
            catch (PostgresException ex) when (ex.SqlState == "22001") // Truncamiento de datos string
            {
                _logger.LogWarning(ex, "Datos muy largos: {MessageText}", ex.MessageText);
                throw new Exception("Uno o más campos exceden la longitud permitida");
            }
            catch (PostgresException ex) when (ex.SqlState == "28P01") // Error de autenticacion
            {
                _logger.LogError(ex, "Error de autenticación con PostgreSQL");
                throw new Exception("Error de conexión con la base de datos. Contacta al administrador");
            }
            catch (PostgresException ex) when (ex.SqlState.StartsWith("23")) // Violaciones de integridad
            {
                _logger.LogWarning(ex, "Violación de integridad: {MessageText}", ex.MessageText);
                throw new Exception("Error en los datos proporcionados. Verifica la información");
            }
            catch (PostgresException ex) when (ex.SqlState.StartsWith("53")) // Recursos insuficientes
            {
                _logger.LogError(ex, "Recursos insuficientes en base de datos: {MessageText}", ex.MessageText);
                throw new Exception("El sistema está experimentando alta demanda. Intenta nuevamente");
            }
            catch (NpgsqlException ex) when (ex.InnerException is System.Net.Sockets.SocketException)
            {
                _logger.LogError(ex, "Error de conexión de red a PostgreSQL");
                throw new Exception("No se puede conectar con la base de datos. Verifica tu conexión de red");
            }
            catch (NpgsqlException ex)
            {
                _logger.LogError(ex, "Error de Npgsql: {Message}", ex.Message);
                throw new Exception("Error temporal en la base de datos. Intenta nuevamente en unos minutos");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error inesperado en DatabaseService");
                throw new Exception("Ocurrió un error inesperado. Por favor, intenta nuevamente");
            }
            finally
            {
                // Asegurar que la conexión se cierre incluso si ocurren errores
                // Previene fugas de conexiones en la base de datos
                if (connection?.State == ConnectionState.Open)
                {
                    await connection.CloseAsync();
                    await connection.DisposeAsync();
                }
            }
        }



        /// <summary>
        /// Ejecuta una función PostgreSQL con manejo mejorado de errores.
        /// Especializado para funciones que retornan mensajes de error estructurados.
        /// </summary>
        /// <param name="funcionCall">Llamada a función PostgreSQL con parámetros nombrados</param>
        /// <param name="parametros">Parámetros para la función</param>
        /// <returns>Tupla con DataTable de resultados y mensaje de error (si aplica)</returns>
        public async Task<(DataTable Result, string ErrorMessage)> ExecuteFunctionWithErrorHandlingAsync(string funcionCall, params NpgsqlParameter[] parametros)
        {
            try
            {
                var resultado = await ExecuteQueryAsync(funcionCall, parametros);
                return (resultado, null)!;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error ejecutando funcion: {Function}", funcionCall);
                return (null, ex.Message)!;
            }
        }


    }
}
