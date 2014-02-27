using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CNX.Shared.Models
{
    public interface ISession : IRequest, ILicence, ISignature
    {
        string Session { get; set; }
        Guid? SessionID { get; set; }
        string SessionHash { get; set; }
        string MachineHash { get; set; }
        string UserHash { get; set; }
        string PublicKey { get; set; }
        string PrivateKey { get; set; }
        DateTime? Created { get; set; }
        DateTime? Expires { get; set; }

    }
}
