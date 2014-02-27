using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using System.Dynamic;
using System.Net;
using System.IO;
using ImpromptuInterface.Dynamic;
using ImpromptuInterface;
using Newtonsoft.Json.Linq;
using System.Collections.Specialized;
using System.Collections;
//using System.Runtime.Remoting.Metadata.W3cXsd2001; //SoapHexBinary.Parse
using MiscUtil.Conversion;
using Org.BouncyCastle.Asn1;

namespace CNX.Shared.Helpers
{
    public static class NexusHelper
    {
        public enum NexusCall
        {
            Address, //A
            Buy, //B
            FirstUpdate, //1
            Describe, //D
            Claim, //C
            Issue, //For = 4
            Transfer, //To = 2
            Endorse, //E
            Resend, //F
            Split,
            Recombine
        }

        public static dynamic ExecuteMethod(NexusCall? call, dynamic parameters)
        {
            var p = new List<object>();
            dynamic un;
            string privateKey;
            string publicKey;
            string hexAddress;
            switch (call)
            {
                case NexusCall.Resend:
                    var oldTx = ExecuteCall("getrawtransaction", parameters.Tx).result.Value;
                    return ExecuteCall("sendrawtransaction", oldTx);
                case NexusCall.Buy:
                    p.Add(1);
                    p.Add(999999);
                    p.Add(new string[] { parameters.FromAddress });
                    un = ExecuteCall("listunspent", p.ToArray());
                    hexAddress = CryptographyHelper.ConvertAddressToPublicHash(parameters.FromAddress).Replace(" ", "").ToLowerInvariant();
                    if (un.result == null || un.result.Count == 0)
                    {
                        un = ExecuteCall("listunspent", null);
                        if (un.result != null && un.result.Count > 0)
                        {
                            hexAddress = null;
                        }
                        else
                        {
                            return null;
                        }
                    }
                    privateKey = CryptographyHelper.ConvertPrivateWIFToHex(ExecuteCall("dumpprivkey", parameters.FromAddress).result.Value).Replace(" ", "");
                    publicKey = CryptographyHelper.ConvertPrivateToPublic(privateKey).Replace(" ", ""); //public key
                    if (hexAddress == null)
                        hexAddress = publicKey;
                    hexAddress = hexAddress.ToLower();
                    foreach (var obj in un.result)
                    {
                        if (obj.scriptPubKey.Value.ToLower().IndexOf(hexAddress) > -1 && obj.amount.Value >= (2 * ConstantsHelper.DEFAULT_FEE_NETWORK) ) //&& obj.confirmations.Value > 3)
                        {
                            var bs = CreateRawBuyTransaction(publicKey, privateKey, parameters.Key, parameters.Rand, obj.amount.Value, obj.txid.Value, obj.scriptPubKey.Value, (int)obj.vout.Value);

                            return ExecuteCall("sendrawtransaction", new object[] { bs });
                        }
                    }
                    return null;
                case NexusCall.FirstUpdate:
                    var buyTx = ExecuteCall("getrawtransaction", new object[]{parameters.Tx, 1});
                    foreach (var obj in buyTx.result.vout)
                    {
                        if (obj.scriptPubKey.type.Value == "nonstandard" && obj.scriptPubKey.hex.Value.IndexOf("51") == 0 && obj.value.Value < (2 * ConstantsHelper.DEFAULT_FEE_NETWORK)) //&& obj.confirmations.Value > 3)
                        {
                            privateKey = CryptographyHelper.ConvertPrivateWIFToHex(ExecuteCall("dumpprivkey", parameters.FromAddress).result.Value).Replace(" ", "");
                            publicKey = CryptographyHelper.ConvertPrivateToPublic(privateKey).Replace(" ", ""); //public key
                            var bs = CreateFirstUpdateTransaction(publicKey, privateKey, parameters.Key, parameters.Rand, parameters.Value, obj.value.Value, parameters.Tx, obj.scriptPubKey.hex.Value, (int)obj.n.Value);

                            return ExecuteCall("sendrawtransaction", new object[] { bs });
                        }
                    }
                    return null;
                case NexusCall.Address:
                    if (parameters.GetType() == typeof(string))
                    {
                        p.Add(parameters.parameters); //bitcoinprivkey
                        p.Add(Guid.NewGuid().ToString()); //label
                        p.Add(false); //rescan
                        return ExecuteCall("importprivkey", p.ToArray());
                    }
                    else
                    {
                        p.Add(parameters.Key); //bitcoinprivkey
                        p.Add(parameters.Label); //label
                        p.Add(parameters.Rescan); //rescan
                        return ExecuteCall("importprivkey", p.ToArray());
                    }
                case NexusCall.Transfer:
                    p.Add(1);
                    p.Add(999999);
                    p.Add(new string[] { parameters.FromAddress });
                    un = ExecuteCall("listunspent", p.ToArray());
                    hexAddress = CryptographyHelper.ConvertAddressToPublicHash(parameters.FromAddress).Replace(" ", "").ToLowerInvariant();
                    if (un.result == null || un.result.Count == 0)
                    {
                        un = ExecuteCall("listunspent", null);
                        if (un.result != null && un.result.Count > 0)
                        {
                            privateKey = ExecuteCall("dumpprivkey", parameters.FromAddress).result.Value;
                            hexAddress = CryptographyHelper.ConvertPrivateToPublic(CryptographyHelper.ConvertPrivateWIFToHex(privateKey)).Replace(" ", ""); //public key
                        }
                    }
                    hexAddress = hexAddress.ToLower();
                    //var address = CryptographyHelper.ConvertPublicHashToAddress(hexAddress, CryptographyHelper.AddressFamily.NMC);
                    foreach (var obj in un.result)
                    {
                        if (obj.scriptPubKey.Value.ToLower().IndexOf(hexAddress) > -1 && obj.amount.Value >= parameters.Amount + ConstantsHelper.DEFAULT_FEE_NETWORK) // && obj.confirmations.Value > 3)
                        {
                            //We can transfer out
                            dynamic origin = new ExpandoObject[1];
                            origin[0] = new ExpandoObject();
                            origin[0].txid = obj.txid.Value;
                            origin[0].vout = obj.vout.Value;
                            //var origins = JsonConvert.SerializeObject(origin);
                            dynamic destination = new ExpandoObject();
                            ((IDictionary<string, object>)destination)[parameters.FromAddress] = obj.amount.Value - parameters.Amount - ConstantsHelper.DEFAULT_FEE_NETWORK;
                            ((IDictionary<string, object>)destination)[parameters.ToAddress] = parameters.Amount;
                            //var destinations = JsonConvert.SerializeObject(destination);
                            var tx = ExecuteCall("createrawtransaction", new object[] { origin, destination });

                            //Sign it
                            var sig = ExecuteCall("signrawtransaction", new object[] { tx.result.Value });

                            //Send it
                            if (!sig.result.complete.Value)
                                throw new Exception("Could not make payment, couldn't sign transaction");

                            return ExecuteCall("sendrawtransaction", new object[] { sig.result.hex.Value });

                            //var txInfo = ExecuteCall("getrawtransaction", new object[] { tx.result.Value });
                        }
                    }
                    return null; //failed
                case NexusCall.Split:
                    List<dynamic> splits = new List<dynamic>();
                    Action<dynamic, string> split = (unspent,address) =>
                    {
                        foreach (var obj in unspent)
                        {
                            if (obj.scriptPubKey.Value.ToLower().IndexOf(address) > -1 && obj.amount.Value >= (parameters.Split*2)) // && obj.confirmations.Value > 3)
                            {
                                //We can transfer out
                                dynamic origin = new ExpandoObject[1];
                                origin[0] = new ExpandoObject();
                                origin[0].txid = obj.txid.Value;
                                origin[0].vout = obj.vout.Value;
                                //var origins = JsonConvert.SerializeObject(origin);
                                dynamic destination = new ExpandoObject();
                                double outstanding = obj.amount.Value - ConstantsHelper.DEFAULT_FEE_NETWORK;
                                for (int i = 0; outstanding > 0; i++)
                                {
                                    ((IDictionary<string, object>)destination)[parameters.FromAddress] = parameters.Split;
                                    outstanding -= parameters.Split;
                                    if (outstanding < 0)
                                        ((IDictionary<string, object>)destination)[parameters.FromAddress] = outstanding*-1;
                                }

                                var tx = ExecuteCall("createrawtransaction", new object[] { origin, destination });

                                ////Sign it
                                //var sig = ExecuteCall("signrawtransaction", new object[] { tx.result.Value });

                                ////Send it
                                //if (!sig.result.complete.Value)
                                //    throw new Exception("Could not make payment, couldn't sign transaction");

                                //splits.Add(ExecuteCall("sendrawtransaction", new object[] { sig.result.hex.Value }));
                                ////var txInfo = ExecuteCall("getrawtransaction", new object[] { tx.result.Value });
                            }
                        }
                    };
                    p.Add(1);
                    p.Add(999999);
                    p.Add(new string[] { parameters.FromAddress });
                    un = ExecuteCall("listunspent", p.ToArray());
                    hexAddress = CryptographyHelper.ConvertAddressToPublicHash(parameters.FromAddress).Replace(" ", "").ToLowerInvariant();
                    if (un.result != null && un.result.Count > 0)
                        split(un.result, hexAddress.ToLower());
                    un = ExecuteCall("listunspent", null);
                    if (un.result != null && un.result.Count > 0)
                    {
                        privateKey = ExecuteCall("dumpprivkey", parameters.FromAddress).result.Value;
                        hexAddress = CryptographyHelper.ConvertPrivateToPublic(CryptographyHelper.ConvertPrivateWIFToHex(privateKey)).Replace(" ", ""); //public key
                        split(un.result, hexAddress.ToLower());
                    }                    
                    //var address = CryptographyHelper.ConvertPublicHashToAddress(hexAddress, CryptographyHelper.AddressFamily.NMC);                    
                    return splits; 
                default:
                    throw new Exception("Could not execute unknown method call.");
            }
        }

        private static string CreateFirstUpdateTransaction(string publicKey, string privateKey, string name, string rand, string val, double balance, string oldHash, string oldPubKey, int oldIndex)
        {
            int version = 28928;
            byte inputCount = 1;
            uint sequence = 4294967295; //FFFFFFFF
            if (balance > ConstantsHelper.DEFAULT_FEE_NETWORK*2)
                throw new Exception("Error, risking too much liability for transaction.");
            long charge = (long)(ConstantsHelper.DEFAULT_FEE_NETWORK * ConstantsHelper.CENT_MULTIPLIER);
            string bs = string.Empty;
            var lenc = new LittleEndianBitConverter();
            var benc = new BigEndianBitConverter();
            var v = BitConverter.ToString(lenc.GetBytes(version)).Replace("-", "");
            var inputs = BitConverter.ToString(new byte[] { Convert.ToByte(inputCount) }).Replace("-", "");
            var index = BitConverter.ToString(lenc.GetBytes(oldIndex)).Replace("-", "");
            var cleanedPubKey = string.Join("", oldPubKey.Reverse().Take(50).Reverse().ToArray());
            var cleanedPubKeyLength = BitConverter.ToString(new byte[] { Convert.ToByte(CryptographyHelper.GetHexBytes(cleanedPubKey).Length) }).Replace("-", "");
            var oldPubKeyLength = BitConverter.ToString(new byte[] { Convert.ToByte(CryptographyHelper.GetHexBytes(oldPubKey).Length) }).Replace("-", "");
            var sequenced = BitConverter.ToString(benc.GetBytes(sequence)).Replace("-", "");
            var cost = BitConverter.ToString(lenc.GetBytes(charge)).Replace("-", "");
            var oldHashReversed = BitConverter.ToString(CryptographyHelper.GetHexBytes(oldHash).Reverse().ToArray()).Replace("-", ""); //Reverse required                            
            var publicHash = CryptographyHelper.ConvertPublicHexToHash(publicKey).Replace(" ", "").ToLowerInvariant();
            var address = CryptographyHelper.ConvertPublicHashToAddress(publicHash, CryptographyHelper.AddressFamily.NMC);
            var bName = BitConverter.ToString(Encoding.ASCII.GetBytes(name)).Replace("-","");
            var bRand = BitConverter.ToString(Encoding.ASCII.GetBytes(rand)).Replace("-", "");
            var bVal = BitConverter.ToString(Encoding.ASCII.GetBytes(val)).Replace("-", "");
            var costedPrefix = string.Format("52{0}{1}{2}{3}{4}{5}6d6d",
                BitConverter.ToString(new byte[] { Convert.ToByte(bName.Length / 2) }).Replace("-", ""),
                bName,
                BitConverter.ToString(new byte[] { Convert.ToByte(bRand.Length / 2) }).Replace("-", ""),
                bRand,
                BitConverter.ToString(new byte[] { Convert.ToByte(bVal.Length / 2) }).Replace("-", ""),
                bVal
                ); //New:1;First:2;Update:3;NOP:4, hash, OP_2DROP OP_DUP OP_HASH160, destination, OP_EQUALVERIFY OP_CHECKS
            var costed = string.Format("76a914{0}88ac", publicHash); 
            var costedLength = BitConverter.ToString(new byte[] { Convert.ToByte(CryptographyHelper.GetHexBytes(costed).Length) }).Replace("-", "");
            var costedWithPrefix = costedPrefix + costed;
            var costedWithPrefixLength = BitConverter.ToString(new byte[] { Convert.ToByte(CryptographyHelper.GetHexBytes(costedPrefix + costed).Length) }).Replace("-", "");
            bs += v;
            bs += inputs;
            bs += oldHashReversed;
            bs += index;
            bs += oldPubKeyLength;
            bs += oldPubKey;
            bs += sequenced;
            bs += "01"; //Output Count
            bs += cost;
            bs += costedWithPrefixLength;
            bs += costedWithPrefix;
            bs += "00000000"; //Lock Time
            bs += "01000000"; //SIGHASH_ALL
            var s256 = CryptographyHelper.Hash256(CryptographyHelper.Hash256(CryptographyHelper.GetHexBytes(bs)));
            var sig = CryptographyHelper.SignWithElliptical(s256, privateKey);
            var bPubKey = publicKey.ToLowerInvariant();
            var bSig = BitConverter.ToString(sig).Replace("-", "").ToLowerInvariant();
            var scriptSig = string.Format("{0}{1}{2}{3}{4}",
                BitConverter.ToString(new byte[] { Convert.ToByte((bSig.Length / 2) + 1) }).Replace("-", ""),
                bSig,
                "01", //HashType=0x01
                BitConverter.ToString(new byte[] { Convert.ToByte(bPubKey.Length / 2) }).Replace("-", ""),
                bPubKey);
            var sigLength = BitConverter.ToString(new byte[] { Convert.ToByte(CryptographyHelper.GetHexBytes(scriptSig).Length) }).Replace("-", "");
            bs = string.Empty;
            bs += v;
            bs += inputs;
            bs += oldHashReversed;
            bs += index;
            bs += sigLength;
            bs += scriptSig;
            bs += sequenced;
            bs += "01"; //Output Count
            bs += cost;
            bs += costedWithPrefixLength;
            bs += costedWithPrefix;
            bs += "00000000"; //Lock Time   
            return bs;
        }

        private static string CreateRawBuyTransaction(string publicKey, string privateKey, string name, string rand, double balance, string oldHash, string oldPubKey, int oldIndex)
        {
            //var address = CryptographyHelper.ConvertPublicHashToAddress(hexAddress, CryptographyHelper.AddressFamily.NMC);
            int version =  28928;
            byte inputCount = 1;            
            //string inputScriptSig = "48304502200902fdd58fd42fba0c6735035969c5579a5adc0f7d5162186b05d66188dd358f0221008e4ce1f385ea5c3d8792f363ad237e242ab5e01b457de1158f38ac451d192dbb014104c6eacb602a3e0786fecbbfe90058c3e23baffd94fb3683677e823eda42b4b0de3e957b1f7f74edf0666bb3a3de46c76647a2af36b090cbd1f63812b04345baa6";
            uint sequence = 4294967295; //FFFFFFFF
            long amount = (long)(balance * ConstantsHelper.CENT_MULTIPLIER);
            long charge = (long)(1.5 * ConstantsHelper.DEFAULT_FEE_NETWORK * ConstantsHelper.CENT_MULTIPLIER);
            string bs = string.Empty;
            var lenc = new LittleEndianBitConverter();
            var benc = new BigEndianBitConverter();
            var v = BitConverter.ToString(lenc.GetBytes(version)).Replace("-", "");
            var inputs = BitConverter.ToString(new byte[] { Convert.ToByte(inputCount) }).Replace("-", "");
            var index = BitConverter.ToString(lenc.GetBytes(oldIndex)).Replace("-", "");
            var cleanedPubKey = string.Join("", oldPubKey.Reverse().Take(50).Reverse().ToArray()); //51141bd6e9164a68802809e53ad10e66a043995de2396d76a914c4e6384021b8b54b88cb68104b8b2229503b8f8388ac
            var cleanedPubKeyLength = BitConverter.ToString(new byte[] { Convert.ToByte(CryptographyHelper.GetHexBytes(cleanedPubKey).Length) }).Replace("-", "");
            var oldPubKeyLength = BitConverter.ToString(new byte[] { Convert.ToByte(CryptographyHelper.GetHexBytes(oldPubKey).Length) }).Replace("-", "");
            var sequenced = BitConverter.ToString(benc.GetBytes(sequence)).Replace("-", "");
            var retain = BitConverter.ToString(lenc.GetBytes(amount - charge)).Replace("-", "");
            var cost = BitConverter.ToString(lenc.GetBytes(charge)).Replace("-", "");
            var oldHashReversed = BitConverter.ToString(CryptographyHelper.GetHexBytes(oldHash).Reverse().ToArray()).Replace("-", ""); //Reverse required                            
            var hash = BitConverter.ToString(CryptographyHelper.Hash160(Encoding.ASCII.GetBytes(rand + name))).Replace("-", "");
            var publicHash = CryptographyHelper.ConvertPublicHexToHash(publicKey).Replace(" ", "").ToLowerInvariant();
            var address = CryptographyHelper.ConvertPublicHashToAddress(publicHash, CryptographyHelper.AddressFamily.NMC);
            //var retained = string.Format("41{1}ac", publicKey); //Default Namecoin Method
            var retained = string.Format("76a914{0}88ac", publicHash);
            var retainedLength = BitConverter.ToString(new byte[] { Convert.ToByte(CryptographyHelper.GetHexBytes(retained).Length) }).Replace("-", "");
            var costedPrefix = string.Format("51{0}{1}6d",
               BitConverter.ToString(new byte[] { Convert.ToByte(hash.Length / 2) }).Replace("-", ""),
               hash
               ); //New:1;First:2;Update:3;NOP:4, hash, OP_2DROP OP_DUP OP_HASH160, destination, OP_EQUALVERIFY OP_CHECKS
            var costed = string.Format("76a914{0}88ac", publicHash);
            var costedLength = BitConverter.ToString(new byte[] { Convert.ToByte(CryptographyHelper.GetHexBytes(costed).Length) }).Replace("-", "");
            var costedWithPrefix = costedPrefix + costed;
            var costedWithPrefixLength = BitConverter.ToString(new byte[] { Convert.ToByte(CryptographyHelper.GetHexBytes(costedPrefix + costed).Length) }).Replace("-", "");
            bs += v;
            bs += inputs;
            bs += oldHashReversed;
            bs += index;
            bs += oldPubKeyLength;
            bs += oldPubKey;
            bs += sequenced;
            bs += "02"; //Output Count
            bs += retain;
            bs += retainedLength;
            bs += retained;
            bs += cost;
            bs += costedWithPrefixLength;
            bs += costedWithPrefix;
            bs += "00000000"; //Lock Time
            //////Could Sign it automatically
            //var sigAuto = ExecuteCall("signrawtransaction", bs);
            //////Send it
            //if (!sigAuto.result.complete.Value)
            //    throw new Exception("Could not make create, couldn't sign transaction");            
            //return sigAuto.result.hex.Value;
            bs += "01000000"; //SIGHASH_ALL
            var s256 = CryptographyHelper.Hash256(CryptographyHelper.Hash256(CryptographyHelper.GetHexBytes(bs)));
            var sig = CryptographyHelper.SignWithElliptical(s256, privateKey);
            var bPubKey = publicKey.ToLowerInvariant();
            var bSig = BitConverter.ToString(sig).Replace("-", "").ToLowerInvariant();
            var scriptSig = string.Format("{0}{1}{2}{3}{4}",
                BitConverter.ToString(new byte[] { Convert.ToByte((bSig.Length / 2) + 1) }).Replace("-", ""),
                bSig,
                "01", //HashType=0x01
                BitConverter.ToString(new byte[] { Convert.ToByte(bPubKey.Length / 2) }).Replace("-", ""),
                bPubKey);
            var sigLength = BitConverter.ToString(new byte[] { Convert.ToByte(CryptographyHelper.GetHexBytes(scriptSig).Length) }).Replace("-", "");
            bs = string.Empty;
            bs += v;
            bs += inputs;
            bs += oldHashReversed;
            bs += index;
            bs += sigLength;
            bs += scriptSig;
            bs += sequenced;
            bs += "02"; //Output Count
            bs += retain;
            bs += retainedLength;
            bs += retained;
            bs += cost;
            bs += costedWithPrefixLength;
            bs += costedWithPrefix;
            bs += "00000000"; //Lock Time
            return bs;
        }

        public static dynamic GetBlocks()
        {
            return ExecuteCall("getblockcount", null).result.Value;
        }

        private static dynamic ExecuteCall(string methodName, object p)
        {
            HttpWebRequest webRequest = (HttpWebRequest)WebRequest.Create("http://localhost:8336");
            webRequest.Credentials = new NetworkCredential("user", "pwd");
            /// important, otherwise the service can't desirialse your request properly
            webRequest.ContentType = "application/json-rpc";
            webRequest.Method = "POST";


            JObject joe = new JObject();
            joe.Add(new JProperty("jsonrpc", "1.0"));
            joe.Add(new JProperty("id", "1"));
            joe.Add(new JProperty("method", methodName));
            
            // params is a collection values which the method requires.
            if (p == null)
            {
                joe.Add(new JProperty("params", new JArray()));
            }
            else if (p.GetType().IsArray)
            {
                var parms = (object[])p;
                JArray props = new JArray();
                foreach (object parm in parms)
                {
                    props.Add(JsonConvert.DeserializeObject(JsonConvert.SerializeObject(parm)));
                }
                //Used named parameters in future versions
                //dynamic o = new ExpandoObject();
                //o.bitcoinprivkey = p[0];
                //var ser = JsonConvert.SerializeObject(o);
                //var pp = JObject.Parse(ser);
                //joe.Add(new JProperty("params", pp));

                joe.Add(new JProperty("params", props));
            }
            else
            {
                joe.Add(new JProperty("params", new JArray(p)));
            }

            // serialize json for the request
            string s = JsonConvert.SerializeObject(joe);
            byte[] byteArray = Encoding.UTF8.GetBytes(s);
            webRequest.ContentLength = byteArray.Length;
            Stream dataStream = webRequest.GetRequestStream();
            dataStream.Write(byteArray, 0, byteArray.Length);
            dataStream.Close();


            try
            {
                WebResponse webResponse = webRequest.GetResponse();
                using (TextReader r = new StreamReader(webResponse.GetResponseStream()))
                using (JsonReader jr = new JsonTextReader(r))
                {
                    var serializer = new JsonSerializer();
                    return serializer.Deserialize(jr);
                }
            }
            catch
            {
                throw new Exception(string.Format("Error processing: {0}. \r\nParameters:\r\n{1}", methodName, JsonConvert.SerializeObject(p)));
            }
            

        }      
        
        public static void Test()
        {
           // var gg = GetBlocks();

    //       var derSig = "304502204c01fee2d724fb2e34930c658f585d49be2f6ac87c126506c0179e6977716093022100faad0afd3ae536cfe11f83afaba9a8914fc0e70d4c6d1495333b2fb3df6e8cae";
    //        var hexSig = "4c01fee2d724fb2e34930c658f585d49be2f6ac87c126506c0179e6977716093faad0afd3ae536cfe11f83afaba9a8914fc0e70d4c6d1495333b2fb3df6e8cae";
    //        //var d2hSig = derSigToHexSig(derSig);
    //        var seq = (DerSequence)DerSequence.FromByteArray(CryptographyHelper.GetHexBytes(derSig));
    //        var derIntR = ((DerInteger)seq.GetObjectAt(0)).Value.ToByteArrayUnsigned();
    //        var derIntS = ((DerInteger)seq.GetObjectAt(1)).Value.ToByteArrayUnsigned();
            

    //    var txn =          ("0100000001a97830933769fe33c6155286ffae34db44c6b8783a2d8ca52ebee6414d399ec300000000" +
    //                    "8a47" +
    //                    "304402202c2e1a746c556546f2c959e92f2d0bd2678274823cc55e11628284e4a13016f80220797e716835f9dbcddb752cd0115a970a022ea6f2d8edafff6e087f928e41baac01" +
    //                    "41" +
    //                    "04392b964e911955ed50e4e368a9476bc3f9dcc134280e15636430eb91145dab739f0d68b82cf33003379d885a0b212ac95e9cddfd2d391807934d25995468bc55" +
    //                    "ffffffff02015f0000000000001976a914c8e90996c7c6080ee06284600c684ed904d14c5c88ac204e000000000000" +
    //                    "1976a914348514b329fda7bd33c7b2336cf7cd1fc9544c0588ac00000000");
    //    var myTxn_forSig = ("0100000001a97830933769fe33c6155286ffae34db44c6b8783a2d8ca52ebee6414d399ec300000000" +
    //                    "1976a914" + "167c74f7491fe552ce9e1912810a984355b8ee07" + "88ac" +
    //                    "ffffffff02015f0000000000001976a914c8e90996c7c6080ee06284600c684ed904d14c5c88ac204e000000000000" +
    //                    "1976a914348514b329fda7bd33c7b2336cf7cd1fc9544c0588ac00000000" +
    //                    "01000000");
    //    //Console.Write(myTxn_forSig);
    //    var public_key =    "04392b964e911955ed50e4e368a9476bc3f9dcc134280e15636430eb91145dab739f0d68b82cf33003379d885a0b212ac95e9cddfd2d391807934d25995468bc55";
    //    var hashToSign = BitConverter.ToString(CryptographyHelper.Hash256(CryptographyHelper.Hash256(CryptographyHelper.GetHexBytes(myTxn_forSig)))).Replace("-", "");
    //    var hashToSign2 = BitConverter.ToString(CryptographyHelper.Hash256(CryptographyHelper.Hash256(CryptographyHelper.GetHexBytes("abbba12345")))).Replace("-", "");
    //    //    //hashlib.sha256(hashlib.sha256(myTxn_forSig.decode('hex')).digest()).digest().encode('hex')
    //    var sig_der =       "304402202c2e1a746c556546f2c959e92f2d0bd2678274823cc55e11628284e4a13016f80220797e716835f9dbcddb752cd0115a970a022ea6f2d8edafff6e087f928e41baac"; //01"[:-2]
    //    var sig = "304402202c2e1a746c556546f2c959e92f2d0bd2678274823cc55e11628284e4a13016f80220797e716835f9dbcddb752cd0115a970a022ea6f2d8edafff6e087f928e41baac01";
            
    //    var res = CryptographyHelper.VerifyElliptical(CryptographyHelper.GetHexBytes(hashToSign), public_key, CryptographyHelper.GetHexBytes(sig));

            
    //        //            string npv, npu, nad;
    //        //CryptographyHelper.GenerateKeys(out npu, out npv, out nad, CryptographyHelper.AddressFamily.NMC);
    //        //var s = CryptographyHelper.SignWithElliptical(CryptographyHelper.GetHexBytes(hashToSign), npv);
    //        //var res2 = CryptographyHelper.VerifyElliptical(CryptographyHelper.GetHexBytes(hashToSign), npu, s);
    //        //var x = BitConverter.ToString(s).Replace("-", "");


    ////            parsed = parseTxn(txn)      
    ////signableTxn = getSignableTxn(parsed)
    ////hashToSign = hashlib.sha256(hashlib.sha256(signableTxn.decode('hex')).digest()).digest().encode('hex')
    ////assert(parsed[1][-2:] == '01') # hashtype
    ////sig = keyUtils.derSigToHexSig(parsed[1][:-2])
    ////public_key = parsed[2]
    ////vk = ecdsa.VerifyingKey.from_string(public_key[2:].decode('hex'), curve=ecdsa.SECP256k1)
    ////assert(vk.verify_digest(sig.decode('hex'), hashToSign.decode('hex')))

    //        var temp = "asd";
    //    //sig = derSigToHexSig(sig_der)

    //    //vk = ecdsa.VerifyingKey.from_string(public_key[2:].decode('hex'), curve=ecdsa.SECP256k1)
    //    //self.assertEquals(vk.verify_digest(sig.decode('hex'), hashToSign.decode('hex')), True)

    //        //string npv, npu, nad;
    //        //CryptographyHelper.GenerateKeys(out npu, out npv, out nad, CryptographyHelper.AddressFamily.NMC);
    //        //var temp = ExecuteMethod(NexusCall.CreateAddress, new { Key = npv.ConvertPrivateHexToWIF(), Label = "Item6", Rescan = false });
    //        //var temp = ExecuteMethod(NexusCall.CreateAddress, npv);

    //        //var addresses =  new SortedDictionary<string, string>();
    //        //string npv, npu, nad;
    //        //for (int i = 0; i < 50; i++)
    //        //{
    //        //    CryptographyHelper.GenerateKeys(out npu, out npv, out nad, CryptographyHelper.AddressFamily.NMC);
    //        //    addresses.Add(nad, npv);
    //        //}
    //        //addresses.Keys.ToArray();
    //        //addresses.Values.ToArray();
    //        //var a = addresses.ToArray();

    //        //var pu = CryptographyHelper.ConvertPrivateToPublic(CryptographyHelper.ConvertPrivateWIFToHex(pv.result.Value)).Replace(" ", "");
    //        var hash = CryptographyHelper.ConvertPublicHexToHash("04ebf207b349e1fc75f6c14c6616afc2d4bcdfa672232234c23c6f34eeba9d10085724cedc2e7d17c427a09cf6068ebfc1bb9da03fd70a27765d2af29adfd6673a");
    //        //var address = CryptographyHelper.ConvertPublicHashToAddress(CryptographyHelper.ConvertPublicHexToHash("04ebf207b349e1fc75f6c14c6616afc2d4bcdfa672232234c23c6f34eeba9d10085724cedc2e7d17c427a09cf6068ebfc1bb9da03fd70a27765d2af29adfd6673a"), CryptographyHelper.AddressFamily.NMC);
    //        var address = CryptographyHelper.ConvertPublicHashToAddress(CryptographyHelper.ConvertPublicHexToHash("04e393db95595e738cde0e1cf650544c13184fca60e6e7e2768244bfd668e5d6d3c51cc0b98d76cecdddc6989c6f3dd34da3581352edac76edf6c0809fc9a05ec7"), CryptographyHelper.AddressFamily.NMC);
    //        //var news1 = CryptographyHelper.ConvertPublicHashToAddress(CryptographyHelper.ConvertPublicHexToHash("04ba207043c1575208f08ea6ac27ed2aedd4f84e70b874db129acb08e6109a3bbb7c479ae22565973ebf0ac0391514511a22cb9345bdb772be20cfbd38be578b0c"), CryptographyHelper.AddressFamily.NMC);
    //        //var news2 = CryptographyHelper.ConvertPublicHashToAddress(CryptographyHelper.ConvertPublicHexToHash("04fc4366270096c7e40adb8c3fcfbff12335f3079e5e7905bce6b1539614ae057ee1e61a25abdae4a7a2368505db3541cd81636af3f7c7afe8591ebc85b2a1acdd"), CryptographyHelper.AddressFamily.NMC);
    //        //CreateNameTransaction();
    //        var add = CryptographyHelper.ConvertPublicHashToAddress("c4e6384021b8b54b88cb68104b8b2229503b8f83", CryptographyHelper.AddressFamily.NMC);
    //        var add2 = CryptographyHelper.ConvertPublicHashToAddress("24e1a9eb65eb2088432dae8e7abfda687771def4", CryptographyHelper.AddressFamily.NMC); //MywNrwnS9QtNkPBLX9sXKaR9iXv9dFPrG5 name_firstupdate
    //        //var r = CryptographyHelper.GetHexBytes("80c5da499c7e9fd100");
    //        //var k = CryptographyHelper.GetHexBytes("642f74657374313031");
    //        //byte[] rk = new byte[r.Length + k.Length];
    //        //System.Buffer.BlockCopy(r, 0, rk, 0, r.Length);
    //        //System.Buffer.BlockCopy(k, 0, rk, r.Length, k.Length);
    //        //var o = BitConverter.ToString(CryptographyHelper.Hash160(rk));

            //var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            //var random = new Random();
            //var result = new string(
            //    Enumerable.Repeat(chars, 8)
            //              .Select(s => s[random.Next(s.Length)])
            //              .ToArray());

            //var tempb = ExecuteMethod(NexusCall.Buy, new
            //{
            //    FromAddress = ConstantsHelper.TRUSTED_ADDRESSES[1],
            //    Key = "d/gabboncha3",
            //    Rand = "randlebomp"
            //});


            //var tempf = ExecuteMethod(NexusCall.FirstUpdate, new
            //{
            //    FromAddress = ConstantsHelper.TRUSTED_ADDRESSES[1],
            //    Key = "d/gabboncha3",
            //    Rand = "randlebomp",
            //    Tx = //tempb.result.Value, 
            //        "407e6f95157946c06d76921b535b1d5027dc4270176985055c0a24607c3a645a",
            //    Value = "{test:true}"
            //});

            //var tempr = ExecuteMethod(NexusCall.Resend, new
            //{
            //    Tx = "680a322c457caae0b9980b596d0b3b4f776808bad79c9bc0fdb41eb4078c0aaa",
            //});


            //var xxx = Encoding.ASCII.GetString(CryptographyHelper.GetHexBytes("520b642f676162626f6e6368610a72616e646c65626f6d700b7b746573743a747275657d6d6d76a91424e1a9eb65eb2088432dae8e7abfda687771def488ac"));

            //var tempt = ExecuteMethod(NexusCall.Transfer, new
            //{
            //    FromAddress = ConstantsHelper.TRUSTED_ADDRESSES[1],
            //    ToAddress = ConstantsHelper.TRUSTED_ADDRESSES[0],
            //    Amount = 0.01
            //});

            var tempt = ExecuteMethod(NexusCall.Split, new
            {
                FromAddress = ConstantsHelper.TRUSTED_ADDRESSES[1],
                Split = 0.60
            });

            //var oldPubKey = "51141bd6e9164a68802809e53ad10e66a043995de2396d76a914c4e6384021b8b54b88cb68104b8b2229503b8f8388ac";
            //var hh = "76a914c4e6384021b8b54b88cb68104b8b2229503b8f8388ac".Length;
            //var xx = string.Join("", oldPubKey.Reverse().Take(50).Reverse().ToArray());
            //var testClean = (oldPubKey.IndexOf("76a914") != 0) oldPubKey.Substring(oldPubKey.IndexOf("76a914")); //51141bd6e9164a68802809e53ad10e66a043995de2396d76a914c4e6384021b8b54b88cb68104b8b2229503b8f8388ac
            
        }
    }
}
