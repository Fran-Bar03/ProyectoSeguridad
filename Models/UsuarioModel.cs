namespace Models
{
    public class UsuarioModel
    {
        /// <summary>
        /// Identificador unico del usuario en el sistema
        /// Este valor numerico es generado automatico por la base de datos mediante SERIAL
        /// Sirve como llave primaria para todas las operaciones de base de datos
        /// </summary>
        public int IdUsuario { get; set; }


        /// <summary>
        /// Nombre o nombres del usuario
        /// Campo obligatorio con una longitud maxima de 100 caracteres
        /// Este campo se valida tanto en la applicacion web como en la BD.
        /// </summary>
        public string? Nombre { get; set; }

        /// <summary>
        /// Apellido paterno del usuario
        /// Campo obligatorio que forma parte de la informacion basica del usuario
        /// Longitud de maxima de 100 caracteres
        /// </summary>
        public string? ApellidoPaterno { get; set; }


        /// <summary>
        /// Apellido materno del usuario
        /// Campo obligatorio que forma parte de la informacion basica del usuario
        /// Longitud maxima de 100 caracteres
        /// </summary>
        public string? ApellidoMaterno  { get; set; }


        /// <summary>
        /// Direccion de correo electronico unica del usuario
        /// Se utiliza como identificador principal para el login y debe ser unico en el sistema
        /// Se valida con formato email
        /// </summary>
        public string? Email { get; set; }


        /// <summary>
        /// Hash seguro de contraseña para el usuario
        /// Se genera el hash usando el algoritmo BCrypt con salt automatico
        /// No se almacena la contraseña en texto plano por razones de seguridad
        /// </summary>
        public string? PasswordHash { get; set; }


        /// <summary>
        /// Fecha y hora en que el usuario fue registrado en el sistema
        /// Este valor se establece automaticamente en la base de datos al momento del registro
        /// Utiliza zona horaria de Hermosillo como referencia
        /// </summary>
        public DateTime FechaRegistro { get; set; }
    }
}
