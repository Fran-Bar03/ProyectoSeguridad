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

       
        public DateTime TokenExpiraUtc { get; set; }
        public DateTime TokenGeneradoUtc { get; set; }
        public DateTime TokenExpiraHermosillo { get; set; }
        public DateTime TokenGeneradoHermosillo { get; set; }

        public int MinutosRestantes { get; set; }
        public int SegundosRestantes { get; set; }  //Para mayor precisión
        public List<ClaimInfo> Claims { get; set; } = new List<ClaimInfo>();
        public string? TokenPreview { get; set; }
        public string? TokenUltimosCaracteres { get; set; }

        //Timestamp Unix para JavaScript
        public long ExpiraUnixTimestamp { get; set; }
        public long GeneradoUnixTimestamp { get; set; }
    }

    public class ClaimInfo
    {
        public string? Tipo { get; set; }
        public string? Valor { get; set; }
        public string? Descripcion { get; set; }
    }
}
