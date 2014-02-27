using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ProtoBuf;


namespace CNX.Shared.Models
{
    [ProtoContract]
    public class SessionRequest : ILicence, ISession, IRequest, ISignature, ISessionEncrypted
    {
        [ProtoMember(1, IsRequired = false)]
        public Guid? ContactID { get; set; }
        [ProtoMember(2, IsRequired = false)]
        public Guid? CompanyID { get; set; }
        [ProtoMember(3, IsRequired = false)]
        public Guid? ProductID { get; set; }
        [ProtoMember(4, IsRequired = false)]
        public Guid? LicenseID { get; set; }
        [ProtoMember(5, IsRequired = false)]
        public string Username { get; set; }
        [ProtoMember(6, IsRequired = false)]
        public string Password { get; set; }
        [ProtoMember(7, IsRequired = false)]
        public Dictionary<Guid, string> MemberRoles { get; set; }
        [ProtoMember(8, IsRequired = false)]
        public Dictionary<Guid, string> MemberCompanies { get; set; }
        [ProtoMember(9, IsRequired = false)]
        public Guid? SessionID { get; set; }
        [ProtoMember(10, IsRequired = false)]
        public string SessionHash { get; set; }
        [ProtoMember(11, IsRequired = false)]
        public string MachineHash { get; set; }
        [ProtoMember(12, IsRequired = false)]
        public string UserHash { get; set; }
        [ProtoMember(13, IsRequired = false)]
        public string PublicKey { get; set; }
        [ProtoMember(14, IsRequired = false)]
        public string PrivateKey { get; set; }
        [ProtoMember(15, IsRequired = false)]
        public DateTime? Created { get; set; }
        [ProtoMember(16, IsRequired = false)]
        public DateTime? Expires { get; set; }
        [ProtoMember(17, IsRequired = false)]
        public string Reference { get; set; }
        [ProtoMember(18, IsRequired = false)]
        public string Nonce { get; set; }
        [ProtoMember(19, IsRequired = false)]
        public string Signature { get; set; }
        [ProtoMember(20, IsRequired = false)]
        public Guid? AuthorisedByCompanyID { get; set; }
        [ProtoMember(21, IsRequired = false)]
        public string RequestSessionKey { get; set; }
        [ProtoMember(22, IsRequired = false)]
        public Guid? RequestSessionNonce { get; set; }
        [ProtoMember(23, IsRequired = false)]
        public string ResponseSessionKey { get; set; }
        [ProtoMember(24, IsRequired = false)]
        public Guid? ResponseSessionNonce { get; set; }
        [ProtoMember(25, IsRequired = false)]
        public DateTime? EncryptedSessionExpiry { get; set; }
        
        [ProtoMember(32, IsRequired = false)]
        public string Session { get; set; }

    }
}
