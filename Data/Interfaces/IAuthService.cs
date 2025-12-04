using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using DTOs.Inicio;
using Models;

namespace Data.Interfaces
{
    public interface IAuthService
    {
        public Task<(bool sucess, string message, int? userId)> RegitrarUsuarioAsync(RegistrarDto registrarDto);
        public Task<(UsuarioModel usuario, string message)> ValidarLoginAsync(LoginDto loginDto, string ipAddress);
    }
}
