using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CookComputing.XmlRpc;
using CNX.Shared.Models;
using System.Web;
using CNX.Shared.Helpers;
using ImpromptuInterface.Dynamic;
using ImpromptuInterface;
using System.Dynamic;
using System.Configuration;
using ProtoBuf;
using System.IO;

namespace CNX.Shared.Helpers
{
    public static class SessionHelper
    {

        [XmlRpcUrl("http://crednexus.com/xmlrpc")]
        public interface IStateName : IXmlRpcProxy
        {
            [XmlRpcMethod("license.getContactInfo")]
            string GetContactInfo(string licence);

            [XmlRpcMethod("license.renewSession")]
            string RenewSession(string licence);
        }

        public static ILicence GetContactInfo(SessionRequest m)
        {
            IStateName proxy = XmlRpcProxyGen.Create<IStateName>();
            proxy.Url = ConstantsHelper.PROVIDER_URL_DEFAULT;
            m.Nonce = GuidHelper.Nonce;
            var response = proxy.GetContactInfo(m.Encrypt<SessionRequest>(ConstantsHelper.KEY_PUBLIC_DEFAULT));
            if (string.IsNullOrWhiteSpace(response))
                throw new System.Security.SecurityException("Could not retrieve secure contact details from service.");
            return CryptographyHelper.VerifyAndDeserialize<SessionRequest>(response, ConstantsHelper.KEY_PUBLIC_DEFAULT);
            
        }

        public static ISession RenewSession(SessionRequest m)
        {
            IStateName proxy = XmlRpcProxyGen.Create<IStateName>();
            proxy.Url = ConstantsHelper.PROVIDER_URL_DEFAULT;
            m.Nonce = GuidHelper.Nonce;
            m.MachineHash = Convert.ToBase64String(MachineHelper.GetMachineHash());
            var response = proxy.RenewSession(m.Encrypt<SessionRequest>(ConstantsHelper.KEY_PUBLIC_DEFAULT));
            if (string.IsNullOrWhiteSpace(response))
                return null;
            return CryptographyHelper.VerifyAndDeserialize<SessionRequest>(response, ConstantsHelper.KEY_PUBLIC_DEFAULT);

        }

        private static SessionRequest _licence = new SessionRequest
            {
                Username = "test",
                Password = "password",
                RequestSessionNonce = GuidHelper.NewComb(),
                RequestSessionKey = CryptographyHelper.GenerateKey(256),
                Session = ApplicationSessionAddress
            };
        public static SessionRequest Licence
        {
            get { return _licence; }
            set { _licence = value; }
        }
        
        private static Configuration _applicationConfig = null;
        public static Configuration ApplicationConfig
        {
            get
            {
                if (_applicationConfig == null)
                    _applicationConfig = ConfigurationManager.OpenExeConfiguration(System.Reflection.Assembly.GetEntryAssembly().Location);
                return _applicationConfig;
            }
        }
        private static string _applicationSession = null;
        public static string ApplicationSession
        {
            get
            {
                if (_applicationSession == null)
                {                    
                    var skv = ApplicationConfig.AppSettings.Settings["Session"];
                    if (skv != null)
                    {
                        _applicationSession = skv.Value;
                        return _applicationSession;
                    }
                    else
                        _applicationSession = string.Empty;
                }
                if (_applicationSession == string.Empty)
                {
                    var session = SessionHelper.RenewSession(Licence);
                    if (session == null)
                        _applicationSession = string.Empty;
                    else
                        using (MemoryStream ms = new MemoryStream())
                        {
                            Serializer.Serialize(ms, session);
                            ms.Position = 0;
                            byte[] msg;
                            using (BinaryReader br = new BinaryReader(ms))
                                msg = br.ReadBytes((int)ms.Length);
                            _applicationSession = Convert.ToBase64String(msg);
                            ApplicationConfig.AppSettings.Settings.Add("Session", _applicationSession);
                            ApplicationConfig.Save(ConfigurationSaveMode.Minimal);
                        }
                }
                return _applicationSession;
            }
        }

        private static CryptographyHelper.AddressFamily _defaultFamily = CryptographyHelper.AddressFamily.NMC;
        private static string _applicationSessionKey = null;
        public static string ApplicationSessionKey
        {
            get
            {
                if (_applicationSession == null)
                {
                    var skv = ApplicationConfig.AppSettings.Settings["SessionKey"];
                    if (skv != null)
                    {
                        _applicationSessionKey = skv.Value;
                    }
                    else
                    {
                        CryptographyHelper.GenerateKeys(out _applicationSessionPublicKey, out _applicationSessionKey, out _applicationSessionAddress, _defaultFamily);
                        ApplicationConfig.AppSettings.Settings.Add("SessionKey", _applicationSessionKey);
                        ApplicationConfig.Save(ConfigurationSaveMode.Minimal);

                    }
                }
                return _applicationSessionKey;
            }
        }

        private static string _applicationSessionAddress = null;
        public static string ApplicationSessionAddress
        {
            get
            {
                if (_applicationSessionAddress == null)
                {
                    if (ApplicationSessionKey == null)
                        throw new Exception("Error encountered creating session address.");
                    if (_applicationSessionAddress == null)
                        _applicationSessionAddress = ApplicationSessionPublicKey.ConvertPublicHexToHash().ConvertPublicHashToAddress(_defaultFamily);
                }
                return _applicationSessionAddress;
            }
        }

        private static string _applicationSessionPublicKey = null;
        public static string ApplicationSessionPublicKey
        {
            get
            {
                if (_applicationSessionPublicKey == null)
                {
                    if (ApplicationSessionKey == null)
                        throw new Exception("Error encountered creating session public key.");
                    if (_applicationSessionPublicKey == null)
                        _applicationSessionPublicKey = ApplicationSessionKey.ConvertPrivateToPublic();
                }
                return _applicationSessionPublicKey;
            }
        }


        private static DateTime _nextCheck = DateTime.UtcNow;

        public static bool Valid
        {
            get
            {
                if (string.IsNullOrWhiteSpace(ApplicationSession))
                    return false;
                SessionRequest cachedSession = null;
                using (MemoryStream ms = new MemoryStream(Convert.FromBase64String(ApplicationSession)))
                    cachedSession = Serializer.Deserialize<SessionRequest>(ms);
                if (!cachedSession.Verify<SessionRequest>(ConstantsHelper.KEY_PUBLIC_DEFAULT))
                    return false;
                if (cachedSession == null)
                    return false;
                if (!ValidateSessionID(cachedSession.SessionID.Value))
                    return false;
                if (cachedSession.Expires.HasValue && cachedSession.Expires.Value < DateTime.UtcNow)
                    return false;
                if (string.IsNullOrWhiteSpace(cachedSession.Nonce) || Guid.Parse(cachedSession.Nonce).GetDate() > DateTime.UtcNow.AddDays(1))
                {
                    _applicationSession = string.Empty;
                    if (_nextCheck < DateTime.UtcNow)
                    {
                        _nextCheck = DateTime.UtcNow.AddMinutes(3);
                        return Valid;
                    }
                    return false;
                }
                return true;
            }
        }

        public static Guid GenerateSessionID(byte[] machine = null)
        {
            var id = GuidHelper.NewComb().ToByteArray();
            if (machine == null)
                machine = MachineHelper.GetMachineHash();
            Array.Copy(machine, machine.Length - 6, id, id.Length - 12, 6);
            return new Guid(id);
        }

        public static bool ValidateSessionID(Guid sessionID, byte[] machine = null)
        {
            try
            {
                var date = sessionID.GetDate();
                if (date > DateTime.UtcNow.AddYears(1) || date < DateTime.UtcNow.AddYears(-1))
                    return false;
                if (machine == null)
                    machine = MachineHelper.GetMachineHash();
                var id = sessionID.ToByteArray();
                for (int i = 0; i < 6; i++)
                {
                    if (id[id.Length - 12 + i] != machine[machine.Length - 6 + i])
                        return false;
                }
                return true;
            }
            catch
            {
                return false;
            }

        }

        public static void Test()
        {            
            //var x = Valid;
            //var testAS = ApplicationSession;
            //var testCI = SessionHelper.GetContactInfo(_licence);
            //Console.WriteLine("Done.");
            //Console.ReadLine();
        }


        
    }
}
