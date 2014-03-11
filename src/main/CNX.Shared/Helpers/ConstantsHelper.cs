﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
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
        public static int PROTOCOL_TIMEOUT_DEFAULT = 3000; //3000 milliseconds = 3000
        public static IPAddress PROTOCOL_VERSION_IP_DEFAULT = new IPAddress(new byte[] { 127, 0, 0, 1 });
        public static int PROTOCOL_VERSION_DEFAULT = 37200;
        public static int PROTOCOL_PORT_DEFAULT = 8334;
        public static int PROTOCOL_BLOCK_START = 165392;
        public static string PROTOCOL_HOST_DEFAULT = "nmc.crednexus.com";
        public static int RPC_PORT_DEFAULT = 8336;
        public static string RPC_HOST_DEFAULT = "localhost";
        public static string RPC_USER_DEFAULT = "user";
        public static string RPC_PASSWORD_DEFAULT = "pwd";
        public static double PROTOCOL_FEE_NETWORK_DEFAULT = 0.01;
        public static double CENT_MULTIPLIER = 100000000.0;
        public static double CENT = 1.0 / CENT_MULTIPLIER;
        public static uint[] PEERS = new uint[] {
            0x58cea445, 
            0x2b562f4e, 
            0x291f20b2
        };
        public static string ADDRESSES_PUBLIC = "F9BEB4FE616464720000000000000000BD070000C9467D0F42F5201653010000000000000000000000000000000000FFFF51193744208EFD061653010000000000000000000000000000000000FFFF81BA11AA208E84101653010000000000000000000000000000000000FFFF443C2E57208EAA0A1653010000000000000000000000000000000000FFFF8372BA05208E2F081653010000000000000000000000000000000000FFFF83B30AD6208EE7061653010000000000000000000000000000000000FFFF05095129208E410C1653010000000000000000000000000000000000FFFF05879D6A208E95061653010000000000000000000000000000000000FFFF45844E3C208E5E0F1653010000000000000000000000000000000000FFFF8AF7D58F208EE2061653010000000000000000000000000000000000FFFF92731BF1208E3C201653010000000000000000000000000000000000FFFF54C85461208EE0041653010000000000000000000000000000000000FFFF180FC3A7208E8C111653010000000000000000000000000000000000FFFF5604667D208E71061653010000000000000000000000000000000000FFFFA2D1610E208EA70F1653010000000000000000000000000000000000FFFFAD1935C5208E8F0F1653010000000000000000000000000000000000FFFF4741EAF3208E200E1653010000000000000000000000000000000000FFFF47536480208E9E071653010000000000000000000000000000000000FFFFADA4F1D5208EB80A1653010000000000000000000000000000000000FFFF18BAC3BB208E141C1653010000000000000000000000000000000000FFFF18C02B3C208E771C1653010000000000000000000000000000000000FFFF569E3471208E1D051653010000000000000000000000000000000000FFFF18C18B6E208EE1111653010000000000000000000000000000000000FFFF56A93165208E4C281653010000000000000000000000000000000000FFFF586A47C7208E5B061653010000000000000000000000000000000000FFFF47B58A3E208E23201653010000000000000000000000000000000000FFFF480F78FC208EDA0C1653010000000000000000000000000000000000FFFF484E95E5208E091C1653010000000000000000000000000000000000FFFF3207C302208E760F1653010000000000000000000000000000000000FFFF321F953B208E591C1653010000000000000000000000000000000000FFFFB20310B4208E2A091653010000000000000000000000000000000000FFFF321FBD25208EBB111653010000000000000000000000000000000000FFFF321FBD29208E29091653010000000000000000000000000000000000FFFF4A6E7092208EF10A1653010000000000000000000000000000000000FFFF4A8A68E5208E4C0B1653010000000000000000000000000000000000FFFF4AC16F74208ECF081653010000000000000000000000000000000000FFFFB86272E6208E640D1653010000000000000000000000000000000000FFFF4B9E9729208E29091653010000000000000000000000000000000000FFFFB8A7B944208EA10F1653010000000000000000000000000000000000FFFF32B4747C208E6C211653010000000000000000000000000000000000FFFF601D36E4208E880F1653010000000000000000000000000000000000FFFFBCA5FC17208EDA081653010000000000000000000000000000000000FFFF616B86A0208EF2071653010000000000000000000000000000000000FFFFC0E2FF25208E95061653010000000000000000000000000000000000FFFF62514F07208E53061653010000000000000000000000000000000000FFFFC632B0EF208E8D111653010000000000000000000000000000000000FFFF629BF7D3208E92051653010000000000000000000000000000000000FFFF3E793EAA208EE0031653010000000000000000000000000000000000FFFF4CBA0C68208EDA081653010000000000000000000000000000000000FFFF62CA142D208E2C091653010000000000000000000000000000000000FFFF63FBE574208E2E081653010000000000000000000000000000000000FFFFCC0E1117208E5F0F1653010000000000000000000000000000000000FFFF4E33C193208EC3111653010000000000000000000000000000000000FFFF6B9622DA208EDC081653010000000000000000000000000000000000FFFF6C337740208E47081653010000000000000000000000000000000000FFFF6CCD9161208E3B071653010000000000000000000000000000000000FFFF6F3B2849208EDD081653010000000000000000000000000000000000FFFF71140602208E7C0F1653010000000000000000000000000000000000FFFF76F4CF05208E2F081653010000000000000000000000000000000000FFFF7BA30A8A208E59041653010000000000000000000000000000000000FFFF42D8ED10208E2E081653010000000000000000000000000000000000FFFFD5BD357D208EBB111653010000000000000000000000000000000000FFFF43A6F93F208E6F271653010000000000000000000000000000000000FFFF43ACA8F4208EEE031653010000000000000000000000000000000000FFFF43E1939D208E52031653010000000000000000000000000000000000FFFFD8DAF42C208E2A1C1653010000000000000000000000000000000000FFFF50F3B37A208E";
        //Little Endian
        public static byte[] MAGIC = new byte[] {
                    //0xfa,
                    //0xbf,
                    //0xb5,
                    //0xda
                    0xf9,
                    0xbe,
                    0xb4,
                    0xfe
        };
        private static string magicString = null;
        public static string MAGIC_STRING
        {
            get
            {
                if (magicString == null)
                {
                    magicString = CryptographyHelper.ByteArrayToString(MAGIC);
                }
                return magicString;
            }
        }
        private static uint? magicInt = null;
        public static uint MAGIC_INT
        {
            get
            {
                if (!magicInt.HasValue)
                {
                    magicInt = BitConverter.ToUInt32(MAGIC,0);
                }
                return magicInt.Value;
            }
        }
    }

}
