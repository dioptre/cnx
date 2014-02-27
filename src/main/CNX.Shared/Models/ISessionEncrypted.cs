using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CNX.Shared.Models
{
    public interface ISessionEncrypted : ISession
    {
        string RequestSessionKey { get; set; }
        Guid? RequestSessionNonce { get; set; }
        string ResponseSessionKey { get; set; }
        Guid? ResponseSessionNonce { get; set; }
        DateTime? EncryptedSessionExpiry { get; set; }

    }
}
