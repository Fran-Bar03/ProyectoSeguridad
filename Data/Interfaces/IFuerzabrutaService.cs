using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Data.Interfaces
{
    public interface IFuerzabrutaService
    {

        public Task<(bool bloquedo, int intentos, int restantes, string mensaje)> CheckAndRegisterAttemptAsync(string identificador, string tipo);
        public Task ResetAttemptsAsync(string identificador, string tipo);
    }
}
