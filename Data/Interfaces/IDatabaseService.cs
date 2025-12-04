using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Npgsql;

namespace Data.Interfaces
{
    public interface IDatabaseService
    {
        public  Task<DataTable> ExecuteQueryAsync(string query, params NpgsqlParameter[] parametros);
        public  Task<(DataTable Result, string ErrorMessage)> ExecuteFunctionWithErrorHandlingAsync(string funcionCall, params NpgsqlParameter[] parametros);
    }
}
