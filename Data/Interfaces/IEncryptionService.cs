using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Data.Interfaces
{
    public interface IEncryptionService
    {
        public(string mensajeEncriptado, string llave) EncriptarAES(string mensaje);
        public string DesencriptarAES(string mensajeEncriptado, string llave);
    }
}
