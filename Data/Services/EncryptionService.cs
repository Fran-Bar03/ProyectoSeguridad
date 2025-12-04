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
                _logger.LogInformation("Iniciando proceso de encriptacion para mensaje de longitud: {Length}", mensaje.Length);

                //Crear instancia de AES con configuracion segura
                //Using segura la liberacion adecauada de recursos criptograficos
                using var AesAplicacion = Aes.Create();
                AesAplicacion.KeySize = 256;  //Usar clave de 256 bits (AES-256) -  estandar de seguridad actual
                AesAplicacion.BlockSize = 128;   //Tamano de bloque estandar AES
                AesAplicacion.Mode = CipherMode.CBC;   //Modo cipher block chaining - mas seguro que ECB
                AesAplicacion.Padding = PaddingMode.PKCS7;   //Esquema de padding estandar


                //Genera clave y vector de inicializacion aleatorios
                //Cada operacion usa valores diferentes para mayor seguridad
                AesAplicacion.GenerateKey();
                AesAplicacion.GenerateIV();

                //Crear encryptor con la clave y IV generados
                //El encryptor maneja la transformacion criptografica
                using var encryptor = AesAplicacion.CreateEncryptor(AesAplicacion.Key, AesAplicacion.IV);
                using var ms = new MemoryStream();


                //Realizar la encriptacion usando Cryptostream
                //CryptoStream aplica la transformacion criptografica durante la escritura
                using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                using (var sw = new StreamWriter(cs))
                {
                    sw.Write(mensaje);    //Escribir mensaje a traves del stream criptografico
                }

                //Convertir resultados a formatos adecuados para almacenamiento/transmision
                var mensajeEncriptado = Convert.ToBase64String(ms.ToArray());    //Base 64 para texto seguro

                var llave = Convert.ToBase64String(AesAplicacion.Key) + "|" + Convert.ToBase64String(AesAplicacion.IV);      //Formato compuesto


                _logger.LogInformation("Encriptacion completada con exito");
                return (mensajeEncriptado, llave);

            }
            catch (Exception ex)
            {
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
                _logger.LogInformation("Iniciando proceso de desencriptacion");


                //Validar y parsear el formato de la llave compuesta
                //La llave debe contener exactamente Key y IV separados por |
                var partes = llave.Split('|');
                if (partes.Length != 2)
                    throw new Exception("Formato de llave invalido. Debe ser: key|iv");


                //Convertir de Base 64 a bytes para operaciones criptograficas
                byte[] llaveBytes = Convert.FromBase64String(partes[0]);        //Clave AES
                byte[] ivBytes = Convert.FromBase64String(partes[1]);     //Vector de inicializacion
                byte[] cipherBytes = Convert.FromBase64String(mensajeEncriptado);     //Mensaje encriptado



                //Configurar AES para desencriptacion con los mismos parametros usados en encriptacion
                using var AesAplicacion = Aes.Create();
                AesAplicacion.Key = llaveBytes;            //Misma clave usada para encriptar
                AesAplicacion.IV = ivBytes;               //Mismo IV usado para encriptar
                AesAplicacion.Mode = CipherMode.CBC;      // Mismo modo de operacion
                AesAplicacion.Padding = PaddingMode.PKCS7;      //Mismo esquema de padding


                //Crear decryptor y realizar desencriptacion
                using var decryptor = AesAplicacion.CreateDecryptor(AesAplicacion.Key, AesAplicacion.IV);
                using var ms = new MemoryStream(cipherBytes);
                using var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
                using var sr = new StreamReader(cs);

                //Leer el mensaje desencriptado del stream
                var mensajeOriginal = sr.ReadToEnd();

                _logger.LogInformation("Desencrptacion completa con exito");
                return mensajeOriginal;
            }
            catch (FormatException)
            {
                _logger.LogError("Formato de datos invalidos durante la desencriptacion");
                throw new Exception("Formato de datos invalidos. Verifica que el mensaje y la llave esten en Base64 correctamente");
            }
            catch (CryptographicException ex)
            {
                _logger.LogError("Error criptografico durante la desencriptacion");
                throw new Exception("Error criptografico. La llave puede ser incorrecta o el mensaje esta corrupto");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error inesperado durante desencriptacion");
                throw new Exception("Error al desencriptar el mensaje: " + ex.Message);
            }
        }
    }
}
