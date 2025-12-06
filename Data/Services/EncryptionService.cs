using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics.X86;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Data.Interfaces;
using Microsoft.Extensions.Logging;
using Aes = System.Security.Cryptography.Aes;


namespace Data.Services
{
    /// <summary>
    /// Servicio para operaciones de encriptación y desencriptación usando el algoritmo AES-256.
    /// Implementa AES en modo CBC (Cipher Block Chaining) con padding PKCS7 para seguridad robusta.
    /// Genera llaves únicas para cada operación y maneja errores criptográficos de forma segura.
    /// </summary>
    public class EncryptionService : IEncryptionService
    {
        private readonly ILogger<EncryptionService> _logger;

        /// <summary>
        /// Constructor del servicio de encriptación.
        /// Inicializa el logger para registro de operaciones criptográficas.
        /// </summary>
        /// <param name="logger">Instancia de ILogger para registro de eventos</param>
        public EncryptionService(ILogger<EncryptionService> logger) => _logger = logger;



        /// <summary>
        /// Encripta un mensaje usando el algoritmo AES-256 en modo CBC.
        /// Genera una llave y vector de inicialización (IV) aleatorios para cada operación.
        /// Retorna el mensaje encriptado en Base64 y la llave compuesta (Key|IV).
        /// </summary>
        /// <param name="mensaje">Mensaje en texto plano a encriptar</param>
        /// <returns>
        /// Tupla con:
        /// - mensajeEncriptado: Texto encriptado en formato Base64
        /// - llave: Llave compuesta con formato "Key|IV" en Base64
        /// </returns>
        /// <exception cref="Exception">Excepción con mensaje descriptivo si falla la encriptación</exception>
        public (string mensajeEncriptado, string llave) EncriptarAES(string mensaje)
        {
            try
            {
                // Registrar inicio del proceso de encriptación
                _logger.LogInformation("Iniciando proceso de encriptacion para mensaje de longitud: {Length}", mensaje.Length);

                // Crear y configurar instancia de AES con parámetros de seguridad
                using var AesAplicacion = Aes.Create();
                AesAplicacion.KeySize = 256;      // Configurar clave de 256 bits (máxima seguridad AES)
                AesAplicacion.BlockSize = 128;    // Tamaño de bloque estándar AES (128 bits)
                AesAplicacion.Mode = CipherMode.CBC;  // Modo Cipher Block Chaining (más seguro que ECB)
                AesAplicacion.Padding = PaddingMode.PKCS7; // Esquema de padding estándar PKCS7

                //  Generar llave y vector de inicialización aleatorios
                // Cada operación genera valores únicos para mayor seguridad
                AesAplicacion.GenerateKey();  // Genera clave AES de 256 bits aleatoria
                AesAplicacion.GenerateIV();   // Genera vector de inicialización de 128 bits aleatorio

                //  Crear el objeto encryptor que realizará la transformación criptográfica
                using var encryptor = AesAplicacion.CreateEncryptor(AesAplicacion.Key, AesAplicacion.IV);

                // Crear MemoryStream para almacenar los bytes resultantes en memoria
                using var ms = new MemoryStream();

                //  Realizar la encriptación usando CryptoStream
                // CryptoStream cifra los datos mientras se escriben en el stream
                using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                using (var sw = new StreamWriter(cs))
                {
                    //  Escribir el mensaje original en el StreamWriter
                    // El mensaje pasa por: StreamWriter → CryptoStream → MemoryStream
                    // CryptoStream lo cifra automáticamente durante la escritura
                    sw.Write(mensaje);
                }
                // Los using aseguran que los streams se cierren correctamente

                //  Convertir resultados a formatos seguros para almacenamiento/transmisión
                var mensajeEncriptado = Convert.ToBase64String(ms.ToArray());    // Convierte bytes cifrados a Base64
                var llave = Convert.ToBase64String(AesAplicacion.Key) + "|" +    // Formato: "KeyBase64|IVBase64"
                           Convert.ToBase64String(AesAplicacion.IV);

                // Registrar éxito y retornar resultados
                _logger.LogInformation("Encriptacion completada con exito");
                return (mensajeEncriptado, llave);

            }
            catch (Exception ex)
            {
                //  Manejo de errores - registrar y relanzar excepción con mensaje claro
                _logger.LogError(ex, "Error durante el proceso de encriptacion");
                throw new Exception("Error al encriptar el mensaje:" + ex.Message);
            }
        }

        /// <summary>
        /// Desencripta un mensaje previamente encriptado con AES-256.
        /// Requiere el mensaje encriptado en Base64 y la llave compuesta en formato "Key|IV".
        /// </summary>
        /// <param name="mensajeEncriptado">Mensaje encriptado en formato Base64</param>
        /// <param name="llave">Llave compuesta en formato "Key|IV" en Base64</param>
        /// <returns>Mensaje original en texto plano</returns>
        /// <exception cref="Exception">Excepción con mensaje descriptivo según el tipo de error</exception>
        public string DesencriptarAES(string mensajeEncriptado, string llave)
        {
            try
            {
                // Registrar inicio del proceso de desencriptación
                _logger.LogInformation("Iniciando proceso de desencriptacion");

                //  Validar y parsear el formato de la llave compuesta
                // La llave debe estar en formato: "KeyBase64|IVBase64"
                var partes = llave.Split('|');
                if (partes.Length != 2)
                    throw new Exception("Formato de llave invalido. Debe ser: key|iv");

                // PASO 3: Convertir de Base64 a bytes para operaciones criptográficas
                byte[] llaveBytes = Convert.FromBase64String(partes[0]);        // Convertir parte Key de Base64 a bytes
                byte[] ivBytes = Convert.FromBase64String(partes[1]);           // Convertir parte IV de Base64 a bytes
                byte[] cipherBytes = Convert.FromBase64String(mensajeEncriptado); // Convertir mensaje cifrado de Base64 a bytes

                // Configurar AES para desencriptación con los mismos parámetros usados en encriptación
                using var AesAplicacion = Aes.Create();
                AesAplicacion.Key = llaveBytes;            // Usar la misma clave que se usó para encriptar
                AesAplicacion.IV = ivBytes;                // Usar el mismo IV que se usó para encriptar
                AesAplicacion.Mode = CipherMode.CBC;       // Usar mismo modo de operación (CBC)
                AesAplicacion.Padding = PaddingMode.PKCS7; // Usar mismo esquema de padding (PKCS7)

                // Crear decryptor que realizará la transformación inversa
                using var decryptor = AesAplicacion.CreateDecryptor(AesAplicacion.Key, AesAplicacion.IV);

                // Crear MemoryStream con los bytes cifrados
                using var ms = new MemoryStream(cipherBytes);

                //  Crear CryptoStream para desencriptar mientras se lee
                using var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);

                //  Crear StreamReader para leer el texto desencriptado
                using var sr = new StreamReader(cs);

                //  Leer todo el mensaje desencriptado del stream
                // Los datos pasan por: MemoryStream → CryptoStream → StreamReader
                // CryptoStream los descifra automáticamente durante la lectura
                var mensajeOriginal = sr.ReadToEnd();

                //  Registrar éxito y retornar mensaje original
                _logger.LogInformation("Desencrptacion completa con exito");
                return mensajeOriginal;
            }
            catch (FormatException)
            {
                // Formato Base64 incorrecto
                _logger.LogError("Formato de datos invalidos durante la desencriptacion");
                throw new Exception("Formato de datos invalidos. Verifica que el mensaje y la llave esten en Base64 correctamente");
            }
            catch (CryptographicException ex)
            {
                // Problema criptográfico (llave incorrecta, datos corruptos)
                _logger.LogError("Error criptografico durante la desencriptacion");
                throw new Exception("Error criptografico. La llave puede ser incorrecta o el mensaje esta corrupto");
            }
            catch (Exception ex)
            {
                //  Error general inesperado
                _logger.LogError(ex, "Error inesperado durante desencriptacion");
                throw new Exception("Error al desencriptar el mensaje: " + ex.Message);
            }
        }
    }
}
