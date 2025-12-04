using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace DTOs.Inicio
{
    public class LoginDto
    {
        /// <summary>
        /// Direccion de correo electronico del usuario
        /// Se valida que no este vacio y que tenga formato de email valido
        /// </summary>
        [Required(ErrorMessage = "El correo electrónico es requerido")]
        [EmailAddress(ErrorMessage ="El formato del correo electrónico no es válido")]
        [Display(Name ="Correo Electrónico")]
        public string? Email { get; set; }


        /// <summary>
        /// Contraseña del usuario para autenticacion
        /// Se valida que no esté vacía y se muestra como campo de tipo password en la UI
        /// La longitud mínima se valida en el servicio de autenticación. 
        /// </summary>
        [Required(ErrorMessage ="La contraseña es requerida")]
        [DataType(DataType.Password)]
        [Display(Name ="Password")]
        public string? Password { get; set; }
    }
}
