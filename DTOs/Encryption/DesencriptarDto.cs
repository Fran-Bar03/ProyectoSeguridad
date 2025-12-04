using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DTOs.Encryption
{
    public class DesencriptarDto
    {

        /// <summary>
        /// Mensaje encriptado en formato Base64 que se desea desencriptar
        /// Campo obligatorio que debe contener un mensaje valido encriptado con AES
        /// Se valida que no este vacio y que tenga formato Base64 correcto
        /// </summary>
        [Required(ErrorMessage ="Pega el mensaje encriptado")]
        [Display(Name ="Mensaje Encriptado")]
        public string? MensajeEncriptado {  get; set; }




        /// <summary>
        /// Llave de desencriptacion en formato "key|iv" en Base64
        /// Debe ser la misma llave que se genero durante el proceso de encriptacion
        /// Campo obligatorio validandolo con el formato correcto
        /// </summary>
        [Required(ErrorMessage = "Pega la llave de desencriptacion")]
        [Display(Name ="Llave de desencriptacion")]
        public string? Llave { get; set; }




        /// <summary>
        /// Mensaje original resultante despues del proceso de desencriptacion
        /// Solo se muestra este campo si la desencriptacion fue exitosa
        /// Es de solo lectura en la vista para mostrar el resultado
        /// </summary>
        [Display(Name ="Mensaje original")]
        public string? MensajeOriginal { get; set; }
        



        /// <summary>
        /// Indicador booleano que muestra si el proceso de desencriptacion fue exitoso
        /// Utilizado por la vista para determionar que mensaje mostrar al usuario
        /// Se establece automaticamente durante el procesamiento en el controlador
        /// </summary>
        public bool Exito { get; set; }
        
        
    }
}
