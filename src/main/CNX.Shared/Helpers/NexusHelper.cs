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
using System.Net.Sockets;
using NKD.Helpers;
using System.Security;

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
            Merge
        }

        public enum MessageType
        {
            NotifyTransaction,
            NotifyVersion,
            GetBlocks,
            GetAddresses,
            GetObject,
            NotifyObject,
            NotifyAddresses
        }

        public enum InventoryType : int
        {
            Error = 0,
            Transaction = 1,
            Block = 2
        }

        public static dynamic ExecuteMethod(NexusCall? call, dynamic parameters)
        {
            var p = new List<object>();
            dynamic un;
            string privateKey = CryptographyHelper.ConvertPrivateWIFToHex(ExecuteCall("dumpprivkey", parameters.FromAddress).result.Value);
            string publicKey = CryptographyHelper.ConvertPrivateToPublic(privateKey); //public key
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
                    hexAddress = CryptographyHelper.ConvertAddressToPublicHash(parameters.FromAddress).ToLowerInvariant();
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
                    if (hexAddress == null)
                        hexAddress = publicKey;
                    hexAddress = hexAddress.ToLower();
                    foreach (var obj in un.result)
                    {
                        if (obj.scriptPubKey.Value.ToLower().IndexOf(hexAddress) > -1 && obj.amount.Value >= (2 * ConstantsHelper.PROTOCOL_FEE_NETWORK_DEFAULT)) //&& obj.confirmations.Value > 3)
                        {
                            var bs = CreateRawBuyTransaction(publicKey, privateKey, parameters.Key, parameters.Rand, obj.amount.Value, obj.txid.Value, obj.scriptPubKey.Value, (int)obj.vout.Value);
                            return ExecuteCall("sendrawtransaction", new object[] { bs });
                        }
                    }
                    return null;
                case NexusCall.FirstUpdate:
                    var buyTx = ExecuteCall("getrawtransaction", new object[] { parameters.Tx, 1 });
                    foreach (var obj in buyTx.result.vout)
                    {
                        if (obj.scriptPubKey.type.Value == "nonstandard" && obj.scriptPubKey.hex.Value.IndexOf("51") == 0 && obj.value.Value < (2 * ConstantsHelper.PROTOCOL_FEE_NETWORK_DEFAULT)) //&& obj.confirmations.Value > 3)
                        {
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
                    hexAddress = CryptographyHelper.ConvertAddressToPublicHash(parameters.FromAddress).ToLowerInvariant();
                    if (un.result == null || un.result.Count == 0)
                    {
                        un = ExecuteCall("listunspent", null);
                        if (un.result != null && un.result.Count > 0)
                        {
                            hexAddress = publicKey; //public key
                        }
                    }
                    hexAddress = hexAddress.ToLower();
                    //var address = CryptographyHelper.ConvertPublicHashToAddress(hexAddress, CryptographyHelper.AddressFamily.NMC);
                    foreach (var obj in un.result)
                    {
                        if (obj.scriptPubKey.Value.ToLower().IndexOf(hexAddress) > -1 && obj.amount.Value >= parameters.Amount + ConstantsHelper.PROTOCOL_FEE_NETWORK_DEFAULT) // && obj.confirmations.Value > 3)
                        {
                            //We can transfer out
                            dynamic origin = new ExpandoObject[1];
                            origin[0] = new ExpandoObject();
                            origin[0].txid = obj.txid.Value;
                            origin[0].vout = obj.vout.Value;
                            //var origins = JsonConvert.SerializeObject(origin);
                            dynamic destination = new ExpandoObject();
                            ((IDictionary<string, object>)destination)[parameters.FromAddress] = obj.amount.Value - parameters.Amount - ConstantsHelper.PROTOCOL_FEE_NETWORK_DEFAULT;
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
                    Action<dynamic, string> fnSplit = (unspent, address) =>
                    {
                        foreach (var obj in unspent)
                        {
                            if (obj.scriptPubKey.Value.ToLower().IndexOf(address) > -1 && obj.amount.Value >= (parameters.Split * 2)) // && obj.confirmations.Value > 3)
                            {
                                var bs = CreateSplitTransaction(publicKey, privateKey, parameters.Split, obj.amount.Value, obj.txid.Value, obj.scriptPubKey.Value, (int)obj.vout.Value);
                                splits.Add(ExecuteCall("sendrawtransaction", new object[] { bs }));
                            }
                        }
                    };
                    p.Add(1);
                    p.Add(999999);
                    p.Add(new string[] { parameters.FromAddress });
                    un = ExecuteCall("listunspent", p.ToArray());
                    hexAddress = CryptographyHelper.ConvertAddressToPublicHash(parameters.FromAddress).ToLowerInvariant();
                    if (un.result != null && un.result.Count > 0)
                        fnSplit(un.result, hexAddress);
                    un = ExecuteCall("listunspent", null);
                    if (un.result != null && un.result.Count > 0)
                    {
                        hexAddress = publicKey.ToLowerInvariant(); //public key                        
                        fnSplit(un.result, hexAddress);
                    }
                    return splits;
                case NexusCall.Merge:
                    List<dynamic> toMerge = new List<dynamic>();
                    Action<dynamic, string> fnMerge = (unspent, address) =>
                    {
                        foreach (var obj in unspent)
                        {
                            if (obj.scriptPubKey.Value.ToLower().IndexOf(address) > -1 && obj.amount.Value <= (parameters.HighFilter) && obj.amount.Value >= (parameters.LowFilter)) // && obj.confirmations.Value > 3)
                            {
                                toMerge.Add(new { Hash = obj.txid.Value, Index = (int)obj.vout.Value, PubKey = obj.scriptPubKey.Value, Amount = obj.amount.Value });

                            }
                        }
                    };
                    p.Add(1);
                    p.Add(999999);
                    p.Add(new string[] { parameters.FromAddress });
                    un = ExecuteCall("listunspent", p.ToArray());
                    hexAddress = CryptographyHelper.ConvertAddressToPublicHash(parameters.FromAddress).ToLowerInvariant();
                    if (un.result != null && un.result.Count > 0)
                        fnMerge(un.result, hexAddress);
                    un = ExecuteCall("listunspent", null);
                    if (un.result != null && un.result.Count > 0)
                    {
                        hexAddress = publicKey.ToLowerInvariant(); //public key                        
                        fnMerge(un.result, hexAddress);
                    }
                    if (toMerge.Count < 2)
                        return null; //Nothing to merge
                    return ExecuteCall("sendrawtransaction", new object[] { CreateMergeTransaction(publicKey, privateKey, toMerge.ToArray()) });
                default:
                    throw new Exception("Could not execute unknown method call.");
            }
        }


        private static string CreateMergeTransaction(string publicKey, string privateKey, dynamic[] oldTxs)
        {

            int version = 1;
            uint sequence = 4294967295; //FFFFFFFF
            
            var lenc = new LittleEndianBitConverter();
            var benc = new BigEndianBitConverter();
            var v = CryptographyHelper.ByteArrayToString(lenc.GetBytes(version));
            var sequenced = CryptographyHelper.ByteArrayToString(benc.GetBytes(sequence));
            var publicHash = CryptographyHelper.ConvertPublicHexToHash(publicKey).ToLowerInvariant();
            var address = CryptographyHelper.ConvertPublicHashToAddress(publicHash, CryptographyHelper.AddressFamily.NMC);

            byte inputCount = (byte)oldTxs.Length;
            var inputs = VarInt((ulong)inputCount);
            double charge = -ConstantsHelper.PROTOCOL_FEE_NETWORK_DEFAULT;
            foreach (var oldTx in oldTxs)
                charge += oldTx.Amount;
            if (charge < 0)
                return null;
            var cost = CryptographyHelper.ByteArrayToString(lenc.GetBytes((long)(charge * ConstantsHelper.CENT_MULTIPLIER)));
            var costed = string.Format("76a914{0}88ac", publicHash);
            var costedLength = CryptographyHelper.ByteArrayToString(new byte[] { Convert.ToByte(CryptographyHelper.GetHexBytes(costed).Length) });

            string[] oldHashReversed = new string[oldTxs.Length];
            string[] index = new string[oldTxs.Length];
            for (int i = 0; i < oldTxs.Length; i++)
            {
                oldHashReversed[i] = CryptographyHelper.ByteArrayToString(((byte[])CryptographyHelper.GetHexBytes(oldTxs[i].Hash)).Reverse().ToArray()); //Reverse required     
                index[i] = CryptographyHelper.ByteArrayToString(lenc.GetBytes(oldTxs[i].Index));
            }

            string signed = string.Empty;
            for (int i = 0; i < oldTxs.Length; i++)
            {
                string bsToSign = string.Empty;
                bsToSign += v;
                bsToSign += inputs;
                for (int j = 0; j < oldTxs.Length; j++)
                {

                    bsToSign += oldHashReversed[j] + index[j];
                    if (i == j)
                    {
                        var oldPubKeyLength = CryptographyHelper.ByteArrayToString(new byte[] { Convert.ToByte(CryptographyHelper.GetHexBytes(oldTxs[i].PubKey).Length) });
                        bsToSign += oldPubKeyLength + oldTxs[i].PubKey;
                    }
                    else
                        bsToSign += "00"; //or 0
                    bsToSign += sequenced;
                }
                bsToSign += "01"; //Output Count
                bsToSign += cost;
                bsToSign += costedLength;
                bsToSign += costed;
                bsToSign += "00000000"; //Lock Time
                bsToSign += "01000000"; //SIGHASH_ALL  
                var s256 = CryptographyHelper.Hash256(CryptographyHelper.Hash256(CryptographyHelper.GetHexBytes(bsToSign)));
                var sig = CryptographyHelper.SignWithElliptical(s256, privateKey);
                var bPubKey = publicKey.ToLowerInvariant();
                var bSig = CryptographyHelper.ByteArrayToString(sig).ToLowerInvariant();
                var scriptSig = string.Format("{0}{1}{2}{3}{4}",
                    CryptographyHelper.ByteArrayToString(new byte[] { Convert.ToByte((bSig.Length / 2) + 1) }),
                    bSig,
                    "01", //HashType=0x01
                    CryptographyHelper.ByteArrayToString(new byte[] { Convert.ToByte(bPubKey.Length / 2) }),
                    bPubKey);
                var sigLength = CryptographyHelper.ByteArrayToString(new byte[] { Convert.ToByte(CryptographyHelper.GetHexBytes(scriptSig).Length) });                
                signed += oldHashReversed[i] + index[i] + sigLength + scriptSig + sequenced;

            }                     
           
            string bs = string.Empty;
            bs += v;
            bs += inputs;
            bs += signed;
            bs += "01"; //Output Count
            bs += cost;
            bs += costedLength;
            bs += costed;
            bs += "00000000"; //Lock Time   
            return bs;
        }

        private static string CreateSplitTransaction(string publicKey, string privateKey, double split, double oldAmount, string oldHash, string oldPubKey, int oldIndex)
        {
            int version = 1;
            byte inputCount = 1;
            uint sequence = 4294967295; //FFFFFFFF
            string bs = string.Empty;
            var lenc = new LittleEndianBitConverter();
            var benc = new BigEndianBitConverter();
            var v = CryptographyHelper.ByteArrayToString(lenc.GetBytes(version));
            var inputs = CryptographyHelper.ByteArrayToString(new byte[] { Convert.ToByte(inputCount) });
            var index = CryptographyHelper.ByteArrayToString(lenc.GetBytes(oldIndex));
            var oldPubKeyLength = CryptographyHelper.ByteArrayToString(new byte[] { Convert.ToByte(CryptographyHelper.GetHexBytes(oldPubKey).Length) });
            var sequenced = CryptographyHelper.ByteArrayToString(benc.GetBytes(sequence));
            var oldHashReversed = CryptographyHelper.ByteArrayToString(CryptographyHelper.GetHexBytes(oldHash).Reverse().ToArray()); //Reverse required                            
            var publicHash = CryptographyHelper.ConvertPublicHexToHash(publicKey).ToLowerInvariant();
            var address = CryptographyHelper.ConvertPublicHashToAddress(publicHash, CryptographyHelper.AddressFamily.NMC);
            var outputCount = 0;
            double outstanding = oldAmount - ConstantsHelper.PROTOCOL_FEE_NETWORK_DEFAULT;
            string costs = string.Empty;
            for (; outstanding > 0; outputCount++)
            {
                outstanding -= split;
                double charge = (outstanding < 0) ? outstanding + split : split;
                var cost = CryptographyHelper.ByteArrayToString(lenc.GetBytes((long)(charge * ConstantsHelper.CENT_MULTIPLIER)));
                var costed = string.Format("76a914{0}88ac", publicHash);
                var costedLength = CryptographyHelper.ByteArrayToString(new byte[] { Convert.ToByte(CryptographyHelper.GetHexBytes(costed).Length) });
                costs += cost + costedLength + costed;

            }
            if (costs == string.Empty)
                return null;
            var outputs = VarInt((ulong)outputCount);
            bs += v;
            bs += inputs;
            bs += oldHashReversed;
            bs += index;
            bs += oldPubKeyLength;
            bs += oldPubKey;
            bs += sequenced;
            bs += outputs;
            bs += costs;
            bs += "00000000"; //Lock Time
            bs += "01000000"; //SIGHASH_ALL
            var s256 = CryptographyHelper.Hash256(CryptographyHelper.Hash256(CryptographyHelper.GetHexBytes(bs)));
            var sig = CryptographyHelper.SignWithElliptical(s256, privateKey);
            var bPubKey = publicKey.ToLowerInvariant();
            var bSig = CryptographyHelper.ByteArrayToString(sig).ToLowerInvariant();
            var scriptSig = string.Format("{0}{1}{2}{3}{4}",
                CryptographyHelper.ByteArrayToString(new byte[] { Convert.ToByte((bSig.Length / 2) + 1) }),
                bSig,
                "01", //HashType=0x01
                CryptographyHelper.ByteArrayToString(new byte[] { Convert.ToByte(bPubKey.Length / 2) }),
                bPubKey);
            var sigLength = CryptographyHelper.ByteArrayToString(new byte[] { Convert.ToByte(CryptographyHelper.GetHexBytes(scriptSig).Length) });
            bs = string.Empty;
            bs += v;
            bs += inputs;
            bs += oldHashReversed;
            bs += index;
            bs += sigLength;
            bs += scriptSig;
            bs += sequenced;
            bs += outputs;
            bs += costs;
            bs += "00000000"; //Lock Time   
            return bs;
        }

        private static string CreateFirstUpdateTransaction(string publicKey, string privateKey, string name, string rand, string val, double balance, string oldHash, string oldPubKey, int oldIndex)
        {
            int version = 28928;
            byte inputCount = 1;
            uint sequence = 4294967295; //FFFFFFFF
            if (balance > ConstantsHelper.PROTOCOL_FEE_NETWORK_DEFAULT * 2)
                throw new Exception("Error, risking too much liability for transaction.");
            long charge = (long)(ConstantsHelper.PROTOCOL_FEE_NETWORK_DEFAULT * ConstantsHelper.CENT_MULTIPLIER);
            string bs = string.Empty;
            var lenc = new LittleEndianBitConverter();
            var benc = new BigEndianBitConverter();
            var v = CryptographyHelper.ByteArrayToString(lenc.GetBytes(version));
            var inputs = CryptographyHelper.ByteArrayToString(new byte[] { Convert.ToByte(inputCount) });
            var index = CryptographyHelper.ByteArrayToString(lenc.GetBytes(oldIndex));
            var cleanedPubKey = string.Join("", oldPubKey.Reverse().Take(50).Reverse().ToArray());
            var cleanedPubKeyLength = CryptographyHelper.ByteArrayToString(new byte[] { Convert.ToByte(CryptographyHelper.GetHexBytes(cleanedPubKey).Length) });
            var oldPubKeyLength = CryptographyHelper.ByteArrayToString(new byte[] { Convert.ToByte(CryptographyHelper.GetHexBytes(oldPubKey).Length) });
            var sequenced = CryptographyHelper.ByteArrayToString(benc.GetBytes(sequence));
            var cost = CryptographyHelper.ByteArrayToString(lenc.GetBytes(charge));
            var oldHashReversed = CryptographyHelper.ByteArrayToString(CryptographyHelper.GetHexBytes(oldHash).Reverse().ToArray()); //Reverse required                            
            var publicHash = CryptographyHelper.ConvertPublicHexToHash(publicKey).ToLowerInvariant();
            var address = CryptographyHelper.ConvertPublicHashToAddress(publicHash, CryptographyHelper.AddressFamily.NMC);
            var bName = CryptographyHelper.ByteArrayToString(Encoding.ASCII.GetBytes(name));
            var bRand = CryptographyHelper.ByteArrayToString(Encoding.ASCII.GetBytes(rand));
            var bVal = CryptographyHelper.ByteArrayToString(Encoding.ASCII.GetBytes(val));
            var costedPrefix = string.Format("52{0}{1}{2}{3}{4}{5}6d6d",
                CryptographyHelper.ByteArrayToString(new byte[] { Convert.ToByte(bName.Length / 2) }),
                bName,
                CryptographyHelper.ByteArrayToString(new byte[] { Convert.ToByte(bRand.Length / 2) }),
                bRand,
                CryptographyHelper.ByteArrayToString(new byte[] { Convert.ToByte(bVal.Length / 2) }),
                bVal
                ); //New:1;First:2;Update:3;NOP:4, hash, OP_2DROP OP_DUP OP_HASH160, destination, OP_EQUALVERIFY OP_CHECKS
            var costed = string.Format("76a914{0}88ac", publicHash);
            var costedLength = CryptographyHelper.ByteArrayToString(new byte[] { Convert.ToByte(CryptographyHelper.GetHexBytes(costed).Length) });
            var costedWithPrefix = costedPrefix + costed;
            var costedWithPrefixLength = CryptographyHelper.ByteArrayToString(new byte[] { Convert.ToByte(CryptographyHelper.GetHexBytes(costedPrefix + costed).Length) });
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
            var bSig = CryptographyHelper.ByteArrayToString(sig).ToLowerInvariant();
            var scriptSig = string.Format("{0}{1}{2}{3}{4}",
                CryptographyHelper.ByteArrayToString(new byte[] { Convert.ToByte((bSig.Length / 2) + 1) }),
                bSig,
                "01", //HashType=0x01
                CryptographyHelper.ByteArrayToString(new byte[] { Convert.ToByte(bPubKey.Length / 2) }),
                bPubKey);
            var sigLength = CryptographyHelper.ByteArrayToString(new byte[] { Convert.ToByte(CryptographyHelper.GetHexBytes(scriptSig).Length) });
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
            int version = 28928;
            byte inputCount = 1;
            //string inputScriptSig = "48304502200902fdd58fd42fba0c6735035969c5579a5adc0f7d5162186b05d66188dd358f0221008e4ce1f385ea5c3d8792f363ad237e242ab5e01b457de1158f38ac451d192dbb014104c6eacb602a3e0786fecbbfe90058c3e23baffd94fb3683677e823eda42b4b0de3e957b1f7f74edf0666bb3a3de46c76647a2af36b090cbd1f63812b04345baa6";
            uint sequence = 4294967295; //FFFFFFFF
            long amount = (long)(balance * ConstantsHelper.CENT_MULTIPLIER);
            long charge = (long)(1.5 * ConstantsHelper.PROTOCOL_FEE_NETWORK_DEFAULT * ConstantsHelper.CENT_MULTIPLIER);
            string bs = string.Empty;
            var lenc = new LittleEndianBitConverter();
            var benc = new BigEndianBitConverter();
            var v = CryptographyHelper.ByteArrayToString(lenc.GetBytes(version));
            var inputs = CryptographyHelper.ByteArrayToString(new byte[] { Convert.ToByte(inputCount) });
            var index = CryptographyHelper.ByteArrayToString(lenc.GetBytes(oldIndex));
            var cleanedPubKey = string.Join("", oldPubKey.Reverse().Take(50).Reverse().ToArray()); //51141bd6e9164a68802809e53ad10e66a043995de2396d76a914c4e6384021b8b54b88cb68104b8b2229503b8f8388ac
            var cleanedPubKeyLength = CryptographyHelper.ByteArrayToString(new byte[] { Convert.ToByte(CryptographyHelper.GetHexBytes(cleanedPubKey).Length) });
            var oldPubKeyLength = CryptographyHelper.ByteArrayToString(new byte[] { Convert.ToByte(CryptographyHelper.GetHexBytes(oldPubKey).Length) });
            var sequenced = CryptographyHelper.ByteArrayToString(benc.GetBytes(sequence));
            var retain = CryptographyHelper.ByteArrayToString(lenc.GetBytes(amount - charge));
            var cost = CryptographyHelper.ByteArrayToString(lenc.GetBytes(charge));
            var oldHashReversed = CryptographyHelper.ByteArrayToString(CryptographyHelper.GetHexBytes(oldHash).Reverse().ToArray()); //Reverse required                            
            var hash = CryptographyHelper.ByteArrayToString(CryptographyHelper.Hash160(Encoding.ASCII.GetBytes(rand + name)));
            var publicHash = CryptographyHelper.ConvertPublicHexToHash(publicKey).ToLowerInvariant();
            var address = CryptographyHelper.ConvertPublicHashToAddress(publicHash, CryptographyHelper.AddressFamily.NMC);
            //var retained = string.Format("41{1}ac", publicKey); //Default Namecoin Method
            var retained = string.Format("76a914{0}88ac", publicHash);
            var retainedLength = CryptographyHelper.ByteArrayToString(new byte[] { Convert.ToByte(CryptographyHelper.GetHexBytes(retained).Length) });
            var costedPrefix = string.Format("51{0}{1}6d",
               CryptographyHelper.ByteArrayToString(new byte[] { Convert.ToByte(hash.Length / 2) }),
               hash
               ); //New:1;First:2;Update:3;NOP:4, hash, OP_2DROP OP_DUP OP_HASH160, destination, OP_EQUALVERIFY OP_CHECKS
            var costed = string.Format("76a914{0}88ac", publicHash);
            var costedLength = CryptographyHelper.ByteArrayToString(new byte[] { Convert.ToByte(CryptographyHelper.GetHexBytes(costed).Length) });
            var costedWithPrefix = costedPrefix + costed;
            var costedWithPrefixLength = CryptographyHelper.ByteArrayToString(new byte[] { Convert.ToByte(CryptographyHelper.GetHexBytes(costedPrefix + costed).Length) });
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
            var bSig = CryptographyHelper.ByteArrayToString(sig).ToLowerInvariant();
            var scriptSig = string.Format("{0}{1}{2}{3}{4}",
                CryptographyHelper.ByteArrayToString(new byte[] { Convert.ToByte((bSig.Length / 2) + 1) }),
                bSig,
                "01", //HashType=0x01
                CryptographyHelper.ByteArrayToString(new byte[] { Convert.ToByte(bPubKey.Length / 2) }),
                bPubKey);
            var sigLength = CryptographyHelper.ByteArrayToString(new byte[] { Convert.ToByte(CryptographyHelper.GetHexBytes(scriptSig).Length) });
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

        private static string GetID(string txHex)
        {
            return CryptographyHelper.ByteArrayToString(CryptographyHelper.Hash256(CryptographyHelper.Hash256(CryptographyHelper.GetHexBytes(txHex))).Reverse().ToArray());
        }

        public static dynamic GetBlocks()
        {
            return ExecuteCall("getblockcount", null).result.Value;
        }

        public static List<dynamic> GetPeers()
        {
            IPAddress destinationIP = null;
            try
            {
                destinationIP = Dns.GetHostAddresses(ConstantsHelper.PROTOCOL_HOST_DEFAULT).FirstOrDefault();
            }
            catch { }
            var ok = new List<dynamic>();
            var resp = new List<dynamic>();
            if (destinationIP != null)
                resp = ProcessBroadcastResponse(ExecuteBroadcast(MessageType.GetAddresses, null, destinationIP, ConstantsHelper.PROTOCOL_PORT_DEFAULT)).Addresses;
            else
                resp = ProcessBroadcastResponse(ConstantsHelper.ADDRESSES_PUBLIC).Addresses;
            resp.AsParallel().ForAll((obj) =>
            {
                if (ok.Count < 10 && ExecuteBroadcast(MessageType.NotifyVersion, null, obj.IP, obj.Port) != null)
                    ok.Add(obj);
            });
            return ok;
        }

        public static string GetPeerString(List<dynamic> addresses = default(List<dynamic>))
        {
            if (addresses == null)
                addresses = GetPeers();
            return CreateBroadcast(MessageType.NotifyAddresses, CreateAddressMessage(addresses));
        }

        private static string CreateAddressMessage(List<dynamic> addresses)
        {
            var lenc = new LittleEndianBitConverter();
            var benc = new BigEndianBitConverter();
            var addr = VarInt((ulong)addresses.Count);
            foreach(var obj in addresses) {
                addr += CryptographyHelper.ByteArrayToString(lenc.GetBytes(obj.Timestamp));
                addr += CryptographyHelper.ByteArrayToString(lenc.GetBytes(obj.Service));
                addr += string.Format("00000000000000000000FFFF{0}",CryptographyHelper.ByteArrayToString(lenc.GetBytes(((IPAddress)obj.IP).IPAsInt())));
                addr += CryptographyHelper.ByteArrayToString(benc.GetBytes(obj.Port));
            }
            return addr;            
        }

        static string CreateVersionMessage(IPAddress destinationIP=null, int? destinationPort=default(int?), IPAddress originIP=null, int? originPort=default(int?))
        {
            if (originIP == null)
                originIP = ConstantsHelper.PROTOCOL_VERSION_IP_DEFAULT;
            if (originPort == default(int?))
                originPort = ConstantsHelper.PROTOCOL_PORT_DEFAULT;
            if (destinationIP == null)
                destinationIP = ConstantsHelper.PROTOCOL_VERSION_IP_DEFAULT;
            if (destinationPort == default(int?))
                destinationPort = ConstantsHelper.PROTOCOL_PORT_DEFAULT; 


            var lenc = new LittleEndianBitConverter();
            var benc = new BigEndianBitConverter();
            var version = CryptographyHelper.ByteArrayToString(lenc.GetBytes(ConstantsHelper.PROTOCOL_VERSION_DEFAULT));
            var services = CryptographyHelper.ByteArrayToString(lenc.GetBytes((ulong)1));
            var time = CryptographyHelper.ByteArrayToString(lenc.GetBytes((ulong)NKD.Helpers.DateHelper.Timestamp));
            //var tttt = new IPAddress(new byte[] { 127, 0, 0, 1 }).IPAsInt();
            Func<IPAddress, int, string> fnGetAddress = (ip, port) =>
            {
                return string.Format("{0}00000000000000000000FFFF{1}{2}",
                    services,
                    CryptographyHelper.ByteArrayToString(ip.GetAddressBytes()),
                    CryptographyHelper.ByteArrayToString(benc.GetBytes((short)port)));
            };
            var ip_origin = fnGetAddress(originIP, originPort.Value);
            var ip_destination = fnGetAddress(destinationIP, destinationPort.Value);
            var rand = new Random();
            var r = new byte[8];
            rand.NextBytes(r);
            var nonce = CryptographyHelper.ByteArrayToString(r);
            var subversion = "00";
            var startHeight = CryptographyHelper.ByteArrayToString(lenc.GetBytes((uint)0));
            return string.Format("{0}{1}{2}{3}{4}{5}{6}{7}",
                version,
                services,
                time,
                ip_origin,
                ip_destination,
                nonce,
                subversion,
                startHeight
            );
        }

        private static string CreateBlockMessage()
        {
            var lenc = new LittleEndianBitConverter();
            var benc = new BigEndianBitConverter();
            var version = CryptographyHelper.ByteArrayToString(lenc.GetBytes(ConstantsHelper.PROTOCOL_VERSION_DEFAULT));
            var genesis = "000000000062b72c5e2ceb45fbc8587e807c155b0da735e6483dfba2f0a9c770";
            var recent =  "98d8cf2b2d787bcc5943faef612b423afc28398fa7a59900b46b1a820e940e8f";
            var hash_count = "02";
            var hash_stop = string.Empty.PadLeft(64, '0'); //Hash Stop
            return string.Format("{0}{1}{2}{3}{4}",
                version,
                hash_count,
                CryptographyHelper.ByteArrayToString(CryptographyHelper.GetHexBytes(recent).Reverse().ToArray()),
                CryptographyHelper.ByteArrayToString(CryptographyHelper.GetHexBytes(genesis).Reverse().ToArray()),
                hash_stop
                );
        }


        private static string CreateObjectMessage(string id, InventoryType? inv = InventoryType.Transaction, bool reverse = true)
        {
            var lenc = new LittleEndianBitConverter();
            var version = CryptographyHelper.ByteArrayToString(lenc.GetBytes(ConstantsHelper.PROTOCOL_VERSION_DEFAULT));
            if (reverse)
                id = CryptographyHelper.ByteArrayToString(CryptographyHelper.GetHexBytes(id).Reverse().ToArray());
            if (inv == null)
                inv = InventoryType.Transaction;
            var x = string.Format("{0}{1}{2}",
               "01",
                CryptographyHelper.ByteArrayToString(lenc.GetBytes((int)inv)),
                 id
               );
            return x;
        }

        private static dynamic ProcessBroadcastResponse(string hex)
        {
            if (hex == null || hex == string.Empty || hex.Length < 48)
                return null;
            var bytes = CryptographyHelper.GetHexBytes(hex);
            return ProcessBroadcastResponse(bytes);
        }

        private static dynamic ProcessBroadcastResponse(byte[] bytes) {
            
            dynamic result = new ExpandoObject();
            var lenc = new LittleEndianBitConverter();
            var benc = new BigEndianBitConverter();
            result.Magic = lenc.ToUInt32(bytes, 0);
            result.Command = Encoding.ASCII.GetString(bytes, 4, 12).Replace("\0","");
            result.Length = lenc.ToUInt32(bytes, 16);
            result.Checksum = lenc.ToUInt32(bytes, 20);
            if (bytes.Length < 25)
                return result;
            var payload = new byte[bytes.Length - 24];
            System.Buffer.BlockCopy(bytes, 24, payload, 0, bytes.Length - 24);
            if (result.Checksum != lenc.ToUInt32(CryptographyHelper.Hash256(CryptographyHelper.Hash256(payload)), 0))
                throw new SecurityException("Message header checksum is not identical to payload");
            if (result.Length != payload.Length)
                throw new SecurityException("Message header length is not identical to payload");
            switch ((string)result.Command)
            {
                case "version":
                    result.Version = lenc.ToUInt32(payload, 0);
                    result.Services = lenc.ToUInt64(payload, 4);
                    result.Timestamp = lenc.ToUInt64(payload, 12);
                    result.OriginIP = lenc.ToUInt32(payload, 40);
                    result.OriginPort = benc.ToUInt16(payload, 44);
                    result.DestinationIP = lenc.ToUInt32(payload, 66);
                    result.DestinationPort = benc.ToUInt16(payload, 70);
                    result.Nonce = lenc.ToUInt64(payload, 72);
                    result.Subversion = payload[80];
                    result.StartHeight = lenc.ToUInt32(payload, 81);
                    break;
                case "addr":
                    result.Count = VarLength(payload, 0);
                    int offset = VarOffset(payload, 0);
                    //RuntimeTypeHandle th = result.Count.GetType().TypeHandle;
                    //int offset = *(*(int**)&th + 1);
                    result.Addresses = new List<dynamic>();
                    for (; offset < payload.Length; offset+=30)
                    {
                        var address = new {
                            Timestamp = lenc.ToUInt32(payload, offset),
                            Service = lenc.ToUInt64(payload, offset + 4),
                            IP = new IPAddress((long)lenc.ToUInt32(payload, offset+24)),
                            Port = benc.ToUInt16(payload, offset + 28)
                        };
                        result.Addresses.Add(address);
                    }
                    break;    
                default:
                    result.Payload = payload;
                    break;
            }
            return result;
        }


        private static string CreateBroadcast(MessageType? msgType, string hex=null)
        {
            if (hex == null)
                hex = string.Empty;
            var checksum = CryptographyHelper.ByteArrayToString(CryptographyHelper.Hash256(CryptographyHelper.Hash256(CryptographyHelper.GetHexBytes(hex))), 0, 4);
            var magic = ConstantsHelper.MAGIC_STRING;
            string command = null;
            switch (msgType)
            {
                case MessageType.NotifyTransaction:
                    command = CryptographyHelper.ByteArrayToString(Encoding.ASCII.GetBytes("tx"));
                    break;
                case MessageType.NotifyVersion:
                    command = CryptographyHelper.ByteArrayToString(Encoding.ASCII.GetBytes("version"));
                    break;
                case MessageType.GetBlocks:
                    command = CryptographyHelper.ByteArrayToString(Encoding.ASCII.GetBytes("getblocks"));
                    break;
                case MessageType.GetAddresses:
                    command = CryptographyHelper.ByteArrayToString(Encoding.ASCII.GetBytes("getaddr"));
                    break;
                case MessageType.GetObject:
                    command = CryptographyHelper.ByteArrayToString(Encoding.ASCII.GetBytes("getdata"));
                    break;
                case MessageType.NotifyObject:
                    command = CryptographyHelper.ByteArrayToString(Encoding.ASCII.GetBytes("inv"));
                    break;
                case MessageType.NotifyAddresses:
                    command = CryptographyHelper.ByteArrayToString(Encoding.ASCII.GetBytes("addr"));
                    break;
                default:
                    return null;
            }
            var length = CryptographyHelper.ByteArrayToString(BitConverter.GetBytes(hex.Length / 2));
            if (command.Length > 24 || length.Length > 8)
                return null;
            return string.Format("{0}{1}{2}{3}{4}", magic, command.PadRight(24, '0'), length.PadRight(8, '0'), checksum, hex);
        }

        private static byte[] DownloadSocket(Socket socket)
        {
            int bufferLength = 4096;
            byte[] buffer = new byte[bufferLength];
            using (MemoryStream ms = new MemoryStream())
            {
                int read;
                while ((read = socket.Receive(buffer)) == bufferLength)
                {
                    ms.Write(buffer, 0, read);
                }
                if (read > 0 && read < bufferLength)
                    ms.Write(buffer, 0, read);
                return ms.ToArray();
            }

        }


        private static string ExecuteBroadcast(MessageType? messageType, string hex=null, IPAddress destinationIP = null, int? destinationPort = default(int?), IPAddress originIP = null, int? originPort = default(int?))
        {
            using (var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
            {
                try
                {
                    if (destinationIP == null)
                        destinationIP = ConstantsHelper.PROTOCOL_VERSION_IP_DEFAULT;
                    if (destinationPort == default(int?))
                        destinationPort = ConstantsHelper.PROTOCOL_PORT_DEFAULT;                    
                    socket.ReceiveTimeout = ConstantsHelper.PROTOCOL_TIMEOUT_DEFAULT;                    
                    var connectResult = socket.BeginConnect(destinationIP, destinationPort.Value, null, null);
                    var connectSuccess = connectResult.AsyncWaitHandle.WaitOne(ConstantsHelper.PROTOCOL_TIMEOUT_DEFAULT, true);
                    if (!connectSuccess)
                        return null;
                    if (!socket.Connected)
                        return null;
                    socket.Send(CryptographyHelper.GetHexBytes(CreateBroadcast(MessageType.NotifyVersion, CreateVersionMessage(destinationIP, destinationPort, originIP, originPort))));
                    byte[] bytes = DownloadSocket(socket);
                    //socket.Receive(bytes); //only 1 ack in nmc
                    if (Encoding.ASCII.GetString(bytes).IndexOf("verack") < 0)
                        return null;
                    Action<string> checkHexExists = (hx) =>
                        {
                            if (hex == null || hex.Length == 0)
                                throw new Exception(string.Format("Missing parameter for {0}", messageType));
                        };
                    switch (messageType)
                    {
                        case MessageType.NotifyVersion:
                            return CryptographyHelper.ByteArrayToString(bytes);
                        case MessageType.NotifyTransaction:
                            checkHexExists(hex);
                            socket.Send(CryptographyHelper.GetHexBytes(CreateBroadcast(MessageType.NotifyTransaction, hex)));
                            //return CryptographyHelper.ByteArrayToString(DownloadSocket(socket)); //socket.Receive(bytes); //nothing received
                            return GetID(hex); //TODO CHECK
                        case MessageType.GetBlocks:
                            if (hex == null || hex.Length == 0)
                                hex = CreateBlockMessage();
                            socket.Send(CryptographyHelper.GetHexBytes(CreateBroadcast(MessageType.GetBlocks, hex)));
                            return CryptographyHelper.ByteArrayToString(DownloadSocket(socket));
                        case MessageType.GetAddresses:
                            socket.Send(CryptographyHelper.GetHexBytes(CreateBroadcast(MessageType.GetAddresses)));
                            return CryptographyHelper.ByteArrayToString(DownloadSocket(socket));
                        case MessageType.GetObject:
                            checkHexExists(hex);
                            socket.Send(CryptographyHelper.GetHexBytes(CreateBroadcast(MessageType.GetObject, hex)));
                            return CryptographyHelper.ByteArrayToString(DownloadSocket(socket));
                        case MessageType.NotifyObject:
                            checkHexExists(hex);
                            socket.Send(CryptographyHelper.GetHexBytes(CreateBroadcast(MessageType.NotifyObject, hex)));
                            return CryptographyHelper.ByteArrayToString(DownloadSocket(socket));
                        default:
                            throw new NotImplementedException();
                    }
                }
                catch (SocketException ex)
                {
                    Console.WriteLine("Problem executing {0}. {1}. Error code: {2}.", messageType, ex.Message, ex.ErrorCode);
                    return null;
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                    return null;
                }
                finally
                {
                    if (socket.Connected)
                        socket.Shutdown(SocketShutdown.Both);
                    socket.Close();
                }
            }
        }

        private static string VarInt(ulong val)
        {
            var lenc = new LittleEndianBitConverter();
            if (val < 0xfd)
                return CryptographyHelper.ByteArrayToString(new byte[] {(byte)val});
            else if (val < 0xffff)
                return "FD" + CryptographyHelper.ByteArrayToString(lenc.GetBytes((ushort)val));
            else if (val < 0xffffffff)
                return "FE" + CryptographyHelper.ByteArrayToString(lenc.GetBytes((uint)val));
            else
                return "FF" + CryptographyHelper.ByteArrayToString(lenc.GetBytes((ulong)val));
        }

        private static int VarOffset(byte[] stream, int index)
        {
            if (stream[index] == 0xff)
                return 9;
            else if (stream[index] == 0xfe)
                return 5;
            else if (stream[index] == 0xfd)
                return 3;
            else
                return 1;
        }

        private static dynamic VarLength(byte[] stream, int index)
        {
            var lenc = new LittleEndianBitConverter();
            if (stream[index] == 0xff)
                return lenc.ToUInt64(stream, index + 1);
            else if (stream[index] == 0xfe)
                return lenc.ToUInt32(stream, index + 1);
            else if (stream[index] == 0xfd)
                return lenc.ToUInt16(stream, index + 1);
            else
                return stream[index];
        }

        private static string VarStr(string str)
        {
            return VarInt((ulong)str.Length) + str;
        }

        private static dynamic ExecuteCall(string methodName, object p)
        {
            HttpWebRequest webRequest = (HttpWebRequest)WebRequest.Create(string.Format("http://{0}:{1}", ConstantsHelper.RPC_HOST_DEFAULT, ConstantsHelper.RPC_PORT_DEFAULT));
            webRequest.Credentials = new NetworkCredential(ConstantsHelper.RPC_USER_DEFAULT, ConstantsHelper.RPC_PASSWORD_DEFAULT);
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

            //var xxx = CryptographyHelper.ByteArrayToString(new byte[] { 0xff, 0x01, 0x00 });
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
    //    var hashToSign = CryptographyHelper.ByteArrayToString(CryptographyHelper.Hash256(CryptographyHelper.Hash256(CryptographyHelper.GetHexBytes(myTxn_forSig))));
    //    var hashToSign2 = CryptographyHelper.ByteArrayToString(CryptographyHelper.Hash256(CryptographyHelper.Hash256(CryptographyHelper.GetHexBytes("abbba12345"))));
    //    //    //hashlib.sha256(hashlib.sha256(myTxn_forSig.decode('hex')).digest()).digest().encode('hex')
    //    var sig_der =       "304402202c2e1a746c556546f2c959e92f2d0bd2678274823cc55e11628284e4a13016f80220797e716835f9dbcddb752cd0115a970a022ea6f2d8edafff6e087f928e41baac"; //01"[:-2]
    //    var sig = "304402202c2e1a746c556546f2c959e92f2d0bd2678274823cc55e11628284e4a13016f80220797e716835f9dbcddb752cd0115a970a022ea6f2d8edafff6e087f928e41baac01";
            
    //    var res = CryptographyHelper.VerifyElliptical(CryptographyHelper.GetHexBytes(hashToSign), public_key, CryptographyHelper.GetHexBytes(sig));

            
    //        //            string npv, npu, nad;
    //        //CryptographyHelper.GenerateKeys(out npu, out npv, out nad, CryptographyHelper.AddressFamily.NMC);
    //        //var s = CryptographyHelper.SignWithElliptical(CryptographyHelper.GetHexBytes(hashToSign), npv);
    //        //var res2 = CryptographyHelper.VerifyElliptical(CryptographyHelper.GetHexBytes(hashToSign), npu, s);
    //        //var x = CryptographyHelper.ByteArrayToString(s);


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

    //        //var pu = CryptographyHelper.ConvertPrivateToPublic(CryptographyHelper.ConvertPrivateWIFToHex(pv.result.Value));
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
    //        //var o = CryptographyHelper.ByteArrayToString(CryptographyHelper.Hash160(rk));

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
            //    Amount = ConstantsHelper.PROTOCOL_FEE_NETWORK_DEFAULT*2
            //});

            //var tempt = ExecuteMethod(NexusCall.Split, new
            //{
            //    FromAddress = ConstantsHelper.TRUSTED_ADDRESSES[1],
            //    Split = 0.30
            //});

            //var tempg = ExecuteMethod(NexusCall.Merge, new
            //{
            //    FromAddress = ConstantsHelper.TRUSTED_ADDRESSES[1],
            //    HighFilter = 0.8,
            //    LowFilter = ConstantsHelper.DEFAULT_FEE_NETWORK * 2
            //});


            //ad7c9c005547f1a87f2ba73270b42eb4d73d6885a742337697593d1f2db52896
            //string tx = "01000000013a9921017672f56611d1975e4cb47920f88447dc3e4d5afe8de58e47f01029e2000000008c493046022100af5a42928a3c497b652cf4c663b06adea257dcfaa62e5396a68a1f2e97fb74ee0221008a9ac1e0e2c57934aa90cd82fdd454d86d762d50a539673ccb296658dff6c37c01410438a311e9ab10e0075304318710f855337b1e5a411fa2bd9d1d5147f3723dd2396b2ad9957ffd0bb899f5f5285a5c485410693e8f1f02763d862a5c5a96c81431ffffffff0300879303000000001976a914c4e6384021b8b54b88cb68104b8b2229503b8f8388ac00879303000000001976a914c4e6384021b8b54b88cb68104b8b2229503b8f8388ac7f8d5b00000000001976a914c4e6384021b8b54b88cb68104b8b2229503b8f8388ac00000000";
            //var txid = GetTxID(tx);

            //beaa0b41640b36cac4328861ac5b88da06e64adb6e1299ebadef76b58dc42f46
            //var txTest = "010000000410739B179AECC6197535A8EBE490480AD1DFA1FC942FBD033FE12DC421279E77000000008A47304402202520a2eda128223e185a88abd6c041cd0ee2421b50343a1968e3adc69a074a6a022078ca945c64c749a5bf470c6ad4d19fb3d0a7262323df2364de63830dd2c1c33201410438a311e9ab10e0075304318710f855337b1e5a411fa2bd9d1d5147f3723dd2396b2ad9957ffd0bb899f5f5285a5c485410693e8f1f02763d862a5c5a96c81431FFFFFFFF10739B179AECC6197535A8EBE490480AD1DFA1FC942FBD033FE12DC421279E77010000008A47304402202672e1762928a3114d888037ac0bf01ceebe3c6978bfcf6e79813f2051eb5b3b02203bd13236c43382795939dd9217e173dd7ba38b89e74d49e1232dd3c310c33e2701410438a311e9ab10e0075304318710f855337b1e5a411fa2bd9d1d5147f3723dd2396b2ad9957ffd0bb899f5f5285a5c485410693e8f1f02763d862a5c5a96c81431FFFFFFFF10739B179AECC6197535A8EBE490480AD1DFA1FC942FBD033FE12DC421279E77020000008B483045022100e1ba45b48736351644f0c22ad22ffed4e68fe7fb67dd5eeae5ef1b8ba33ba4580220099a08de5414131e8eef289207c2ed010bee1614f55f96d6e91c3dd793d21b1e01410438a311e9ab10e0075304318710f855337b1e5a411fa2bd9d1d5147f3723dd2396b2ad9957ffd0bb899f5f5285a5c485410693e8f1f02763d862a5c5a96c81431FFFFFFFF10739B179AECC6197535A8EBE490480AD1DFA1FC942FBD033FE12DC421279E77030000008A473044022100bd999ac6fc9df349b39af9b16b09d6624b0e31fbb9d68bb5cf2a25544c5449a3021f4a15b59844d28269d10c46168e1ecaf500903db532725c710e08d48ae0a2fc01410438a311e9ab10e0075304318710f855337b1e5a411fa2bd9d1d5147f3723dd2396b2ad9957ffd0bb899f5f5285a5c485410693e8f1f02763d862a5c5a96c81431FFFFFFFF01C0CB1707000000001976a914c4e6384021b8b54b88cb68104b8b2229503b8f8388ac00000000";
                
            //var oldPubKey = "51141bd6e9164a68802809e53ad10e66a043995de2396d76a914c4e6384021b8b54b88cb68104b8b2229503b8f8388ac";
            //var hh = "76a914c4e6384021b8b54b88cb68104b8b2229503b8f8388ac".Length;
            //var xx = string.Join("", oldPubKey.Reverse().Take(50).Reverse().ToArray());
            //var testClean = (oldPubKey.IndexOf("76a914") != 0) oldPubKey.Substring(oldPubKey.IndexOf("76a914")); //51141bd6e9164a68802809e53ad10e66a043995de2396d76a914c4e6384021b8b54b88cb68104b8b2229503b8f8388ac

            //var c2 = "0100000001484d40d45b9ea0d652fca8258ab7caa42541eb52975857f96fb50cd732c8b481000000008a47304402202cb265bf10707bf49346c3515dd3d16fc454618c58ec0a0ff448a676c54ff71302206c6624d762a1fcef4618284ead8f08678ac05b13c84235f1654e6ad168233e8201410414e301b2328f17442c0b8310d787bf3d8a404cfbd0704f135b6ad4b2d3ee751310f981926e53a6e8c39bd7d3fefd576c543cce493cbac06388f2651d1aacbfcdffffffff0162640100000000001976a914c8e90996c7c6080ee06284600c684ed904d14c5c88ac00000000";
            //var c3 = CryptographyHelper.ByteArrayToString(CryptographyHelper.Hash256(CryptographyHelper.Hash256(CryptographyHelper.GetHexBytes(c2))), 0, 4);



            //var inputs = CryptographyHelper.ByteArrayToString(new byte[] { Convert.ToByte(inputCount) });
            //var tx = "94eb66cf0bc2f833841ad7a2337d280a6c3966dd2c936dfd30645a4feed422e5";
            //ProcessBroadcastResponse(CreateBroadcast(MessageType.Version, CreateVersionMessage()));
            //var ret = ExecuteBroadcast(MessageType.GetBlocks);
            
            //var ret3 = ExecuteBroadcast(MessageType.RetrieveObject, CreateObjectMessage(tx, InventoryType.Transaction, true));
            //var ret4 = ExecuteBroadcast(MessageType.NotifyObject, CreateObjectMessage(tx, InventoryType.Transaction, false));

            GetPeers();
            

        }
    }
}
