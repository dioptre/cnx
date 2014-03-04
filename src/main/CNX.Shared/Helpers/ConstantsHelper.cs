using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CNX.Shared.Helpers
{
    public class ConstantsHelper
    {
        public static string KEY_PUBLIC_DEFAULT = @"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmFOMU+G8BlfctPJS4+DDnT8tjGU05RhYj5aEdZCvM+J8LRhSMastgwRALorOj/Wfk5NEvv6wbV+UIKSD6mPfEnmIQpD3k7nMKk67uxxu03Y/TWZT5Z0NufIHpRB0jtfC+5lpPiWJen+rvJBQmg1sBvipVeVllxMUCwOXV6o61/lghBPFGeXm+88BWb3pwIBoJ5h9lsiQt6jpa4XR2z70waAmxtygKLlf3FJ9uGvU00Ahdwx04uBTyvocih3LRu93X0JuaSQRyg3aiW0NFWtHOXQ7buQKIxswUpzCJijbDyq+ty1rjuuBTChpddRWjWXtZiHoTGuI7GNX36cl0i2LpwIDAQAB";
        public static string PROVIDER_URL_DEFAULT = @"http://crednexus.com/xmlrpc";
        public static string[] TRUSTED_ADDRESSES = new string[] { 
            "NEXUSCK711W5xQ3Pw5HBbiWTUtJLmbvGXz", 
            "NEXUSCAVfEk8nLKkWGBGdERth5sKuqNBjQ", 
            "NEXUSCvftgFVJVknYYZk8MZkb4AaANWhnx" };
        public static string[] TRUSTED_KEYS_PUBLIC = new string[] { 
            "04591C6B8D4B69B0BEE10A33FD1F8A3513227F2CA34FE322BE51B1EE390785F3132C54C9C4D093140A18EDB0E8056319F2F6C9C68B17289C8C675B08655CD4CFE5",
            "0438A311E9AB10E0075304318710F855337B1E5A411FA2BD9D1D5147F3723DD2396B2AD9957FFD0BB899F5F5285A5C485410693E8F1F02763D862A5C5A96C81431",
            "04583060EDE85F8E7BC519C2DC5390F2CA448562F37B293AD17C66C0CD0A0787804818A70BDC3065A065BD7F78124574E4014D757A6E98C58B6D690F7A0ACA83F1"
        };
        public static double DEFAULT_FEE_NETWORK = 0.01;
        public static double CENT_MULTIPLIER = 100000000;
        public static uint[] PEERS = new uint[] {
            0x58cea445, 
            0x2b562f4e, 
            0x291f20b2
        };
        //Little Endian
        public static byte[] MAGIC = new byte[] {
                    0xfa,
                    0xbf,
                    0xb5,
                    0xda
        };
        private static string magicString = null;
        public static string MAGIC_STRING
        {
            get
            {
                if (magicString == null)
                {
                    magicString = CryptographyHelper.ByteArrayToString(MAGIC.Reverse().ToArray());
                }
                return magicString;
            }
        }
        public static uint? magicInt = null;
        public static uint MAGIC_INT
        {
            get
            {
                if (!magicInt.HasValue)
                {
                    magicInt = BitConverter.ToUInt32(MAGIC.Reverse().ToArray(),0);
                }
                return magicInt.Value;
            }
        }
    }

}
