using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CNX.Shared.Helpers;
using System.Runtime.InteropServices;

namespace CNX.Test
{
    class Program
    {
        [DllImport("libsophia.so.1.1.dll", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        private static extern void testDLL(
                [In,Out] StringBuilder lpString
            );

        static void Main(string[] args)
        {
            //SessionHelper.Test();
            //CryptographyHelper.Test();
            //NexusHelper.Test();
            StringBuilder x = new StringBuilder();
            x.Append("fred2");
            testDLL(x);
            Console.Write(x);

            //Use byte[] to pass in char* ie Encoding.Ascii.getBytes

        }
    }
}
