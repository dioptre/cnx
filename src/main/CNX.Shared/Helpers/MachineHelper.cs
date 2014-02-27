using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Management;
using System.IO;
using System.Security.Cryptography;

namespace CNX.Shared.Helpers
{

    public static class MachineHelper
    {

        public static byte[] GetMachineHash() {
            string id = "";
            foreach (var s in GetCPUID().OrderBy(f=>f))
                id += string.Format("{0}", s);
            foreach (var s in GetMACAddresses().OrderBy(f => f))
                id += string.Format("{0}", s);
            id += string.Format("{0}", GetVolumeSerial());
            id += string.Format("{0}", GetWindowsProductKey());
            SHA1 sha = new SHA1CryptoServiceProvider();
            return sha.ComputeHash(System.Text.Encoding.UTF8.GetBytes(id)); //Encoding.UTF8.GetString
        }

        public static List<string> GetCPUID()
        {
            try
            {
                ManagementObjectSearcher searcher =
                    new ManagementObjectSearcher("root\\CIMV2",
                    "SELECT * FROM Win32_Processor");
                List<string> ids = new List<string>();
                foreach (ManagementObject obj in searcher.Get())
                {
                    ids.Add(string.Format("A:{0};C:{1};F:{2};P:{3}", obj["Architecture"], obj["Caption"], obj["Family"], obj["ProcessorId"]));
                    obj.Dispose();
                }
                return ids;
            }
            catch (ManagementException e)
            {
                throw e;
            }
        }

        public static string GetVolumeSerial(string strDriveLetter = "C")
        {
            if (strDriveLetter == "" || strDriveLetter == null) strDriveLetter = "C";
            using (ManagementObject disk = new ManagementObject("win32_logicaldisk.deviceid=\"" + strDriveLetter + ":\""))
            {
                disk.Get();
                return disk["VolumeSerialNumber"].ToString();
            }
        }

        public static List<string> GetMACAddresses()
        {
            ManagementClass mc = new ManagementClass("Win32_NetworkAdapterConfiguration");
            ManagementObjectCollection moc = mc.GetInstances();
            List<string> ids = new List<string>();
            foreach (ManagementObject obj in moc)
            {
                if ((bool)obj["IPEnabled"])
                    ids.Add(obj["MacAddress"].ToString());
                obj.Dispose();
            }
            return ids;
        }

        public static string GetWindowsProductKey()
        {
            using (ManagementObject obj = new ManagementObject("Win32_OperatingSystem=@"))
            {
                obj.Get();
                return (string)obj["SerialNumber"];
            }
        }
    }
}