using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CNX.Shared.Models
{
    public interface ISignature
    {
        string Signature { get; set; }
        Guid? AuthorisedByCompanyID { get; set; }
    }
}
