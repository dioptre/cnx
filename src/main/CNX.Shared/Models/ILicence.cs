using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CNX.Shared.Models
{
    public interface ILicence : IRequest, ISignature
    {
        Guid? ContactID { get; set; }
        Guid? CompanyID { get; set; }
        Guid? ProductID { get; set; }
        Guid? LicenseID { get; set; }
        string Username { get; set; }
        string Password { get; set; }
    }

}
