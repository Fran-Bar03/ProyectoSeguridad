using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DTOs.Inicio
{
    public class RegistrarDto
    {

        /// <summary>
        /// Nombre o nombres del usuario
        /// Campo obligatorio con longitud maxima de 100 caracteres
        /// Se valida que el campo no este vacio y que no exceda la longitud maxima
        /// </summary>
        [Required(ErrorMessage ="El nombre es requerido")]
        [StringLength(100, ErrorMessage ="El nombre no puede exceder de los 100 caracteres")]
        [Display(Name ="Nombre(s)")]
        public string? Nombre {  get; set; }



        /// <summary>
        /// Apellido paterno del usuario
        /// Campo obligatorio con longitud maxima de 100 caracteres
        /// Parte de la informacion personal basica requerida
        /// </summary>
        [Required(ErrorMessage ="El apellido paterno es requerido")]
        [StringLength(100, ErrorMessage ="El apellido paterno no puede exceder los 100 caracteres")]
        [Display(Name ="Apellido Paterno")]
        public string? ApellidoPaterno { get; set; }



        /// <summary>
        /// Apellido materno del usuario
        /// Campo obligatorio con longitud maxima de 100 caracteres
        /// Parte de la informacion personal basica requerida
        /// </summary>
        [Required(ErrorMessage ="El apellido materno es requerido")]
        [StringLength(100, ErrorMessage ="El apellido materno no puede exceder los 100 caracteres")]
        [Display(Name ="Apellido Materno")]
        public string? ApellidoMaterno {  get; set; }




        /// <summary>
        /// Direccion de correo electronico unica del usuario
        /// Se valida como formato email valido y debe ser unico en el sistema
        /// Longitud maxima de 255 caracteres segun estandar de emails
        /// </summary>
        [Required(ErrorMessage ="El correo electrónico es requerido")]
        [EmailAddress(ErrorMessage ="El formato del correo electrónico no es valido")]
        [StringLength(255, ErrorMessage = "El correo electrónico no debe exceder los 255 caracteres")]
        [Display(Name = "Correo Electrónico")]
        public string? Email { get; set; }



        /// <summary>
        /// Contraseña del usuario para la cuenta
        /// Minimo de 6 caracteres por seguridad
        /// Se muestra como camo tipo password para ocultar 6 caracteres
        /// </summary>
        [Required(ErrorMessage ="La contraseña es requerida")]
        [MinLength(6, ErrorMessage = "La contraseña debe tener al menos 6 caracteres")]
        [DataType(DataType.Password)]
        [Display(Name = "Contraseña")]
        public string? Password { get; set; }



        /// <summary>
        /// Confirmacion de contraseña para verificar que no haya errores de tipeo
        /// Debe coincidir exactamente con el campo Password
        /// Validacion automatica mediante el atributo Compare
        /// </summary>
        [Required(ErrorMessage = "Debe confirmar la contraseña")]
        [Compare("Password", ErrorMessage ="Las contraseñas no coinciden")]
        [DataType(DataType.Password)]
        [Display(Name ="Confirmar Contraseña")]
        public string? ConfirmarPassword {  get; set; }
    }
}
