// DTOs/Inicio/TokenInfoViewModel.cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DTOs.Inicio
{
    public class TokenInfoViewModel
    {
        public string? UsuarioEmail { get; set; }
        public string? UsuarioNombreCompleto { get; set; }
        public string? UsuarioId { get; set; }
        public string? TokenGenerado { get; set; }
        public string? TokenExpira { get; set; }


        public DateTime TokenGeneradoUtc { get; set; }
        public DateTime TokenGeneradoHermosillo { get; set; }

        public List<ClaimInfo> Claims { get; set; } = new List<ClaimInfo>();
        public string? TokenPreview { get; set; }
        public string? TokenUltimosCaracteres { get; set; }

        // ======================================================================
        // PROPIEDADES NUEVAS PARA INFORMACIÓN DE DISPOSITIVOS MÓVILES
        // ======================================================================
        /// <summary>
        /// Tipo de dispositivo donde se creó el token
        /// Valores: "mobile" (móvil/tablet) o "desktop" (escritorio)
        /// </summary>
        public string? Dispositivo { get; set; }

        /// <summary>
        /// Vista previa del hash del User-Agent
        /// Muestra los primeros caracteres del hash para identificación
        /// </summary>
        public string? UserAgentHashPreview { get; set; }
    }

    public class ClaimInfo
    {
        public string? Tipo { get; set; }
        public string? Valor { get; set; }
        public string? Descripcion { get; set; }
    }
}