using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CNX.Shared.Models
{
    public interface IRequest 
    {
        string Reference { get; set; }
        string Nonce { get; set; }
    }
}
