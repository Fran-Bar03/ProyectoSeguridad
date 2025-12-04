using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.ComponentModel.DataAnnotations;

namespace DTOs.Encryption
{
    public class EncriptarDto
    {

        /// <summary>
        /// Mensaje original en texto plano que sera encriptado
        /// Campo obligatorio validado tanto el cliente como servidor
        /// No tiene restricciones de longitud pero se recomienda mensajes razonables
        /// </summary>
        [Required(ErrorMessage ="Escribe el mensaje para encriptar")]
        [Display(Name ="Mensaje a encriptar")]
        public string? Mensaje {  get; set; }



        /// <summary>
        /// Mensaje resultante despues de proceso de encriptacion
        /// Se presenta en formato Base64 para facilitar su visualizacion y almacenamiento
        /// Este campo es de solo lectura en la vista despues de la encrptacion
        /// </summary>
        [Display(Name ="Mensaje Encriptado")]
        public string? MensajeEncriptado { get; set; }



        /// <summary>
        /// Llave de encriptacion generada automaticamente durante el proceso
        /// Combinacion de la clave AES y el vector de inicializacion en formato Base64
        /// Es crucial guardar esta llave de forma segura para poder desencriptar posteriormente
        /// </summary>
        [Display(Name = "Llave de Encriptacion")]
        public string? Llave {  get; set; }


    }
}
