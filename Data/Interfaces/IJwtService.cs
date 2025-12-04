using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Models;

namespace Data.Interfaces
{
    public interface IJwtService
    {

        public string GenerarJwtToken(UsuarioModel usuario);
        public ClaimsPrincipal ValidarToken(string token);
    }
}
