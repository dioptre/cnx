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
                            var bs = CreateBuyTransaction(publicKey, privateKey, parameters.Key, parameters.Rand, obj.amount.Value, obj.txid.Value, obj.scriptPubKey.Value, (int)obj.vout.Value);
                            return ExecuteCall("sendrawtransaction", new object[] { bs });
                        }
                    }
                    return null;
                case NexusCall.Describe:
                    var oldName = ExecuteCall("name_show", new object[] { parameters.Key });
                    var oldNameTx = ExecuteCall("getrawtransaction", new object[] { oldName.result.txid.Value, 1 });
                    dynamic oldNameVout = null;
                    foreach (var obj in oldNameTx.result.vout)
                    {
                        if (obj.scriptPubKey.type.Value == "nonstandard" && (obj.scriptPubKey.hex.Value.IndexOf("52") == 0 || obj.scriptPubKey.hex.Value.IndexOf("53") == 0) && obj.value.Value < (2 * ConstantsHelper.PROTOCOL_FEE_NETWORK_DEFAULT)) //&& obj.confirmations.Value > 3)
                        {
                            oldNameVout = obj;
                            break;
                        }
                    }
                    if (oldNameVout == null)
                        return null;
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
                            var bs = CreateUpdateTransaction(publicKey, privateKey, parameters.Key, parameters.Value, obj.amount.Value, obj.txid.Value, obj.scriptPubKey.Value, (int)obj.vout.Value, oldName.result.txid.Value, oldNameVout.scriptPubKey.hex.Value, (int)oldNameVout.n.Value);
                            return ExecuteCall("sendrawtransaction", new object[] { bs });
                            //var bs = CreateBuyTransaction(publicKey, privateKey, parameters.Key, parameters.Rand, obj.amount.Value, obj.txid.Value, obj.scriptPubKey.Value, (int)obj.vout.Value);
                            //return ExecuteCall("sendrawtransaction", new object[] { bs });
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

        private static string CreateUpdateTransaction(string publicKey, string privateKey, string name, string val, double balance, string oldHash, string oldPubKey, int oldIndex, string oldNameHash, string oldNamePubKey, int oldNameIndex)
        {
            int version = 28928;
            uint sequence = 4294967295; //FFFFFFFF

            var lenc = new LittleEndianBitConverter();
            var benc = new BigEndianBitConverter();
            var v = CryptographyHelper.ByteArrayToString(lenc.GetBytes(version));
            var sequenced = CryptographyHelper.ByteArrayToString(benc.GetBytes(sequence));
            var publicHash = CryptographyHelper.ConvertPublicHexToHash(publicKey).ToLowerInvariant();
            var address = CryptographyHelper.ConvertPublicHashToAddress(publicHash, CryptographyHelper.AddressFamily.NMC);
           
            var inputs = "02";
            long amount = (long)(balance * ConstantsHelper.CENT_MULTIPLIER);
            long charge = (long)(ConstantsHelper.PROTOCOL_FEE_NETWORK_DEFAULT * ConstantsHelper.CENT_MULTIPLIER);
            var retain = CryptographyHelper.ByteArrayToString(lenc.GetBytes(amount - charge));
            var cost = CryptographyHelper.ByteArrayToString(lenc.GetBytes(charge));
            var retained = string.Format("76a914{0}88ac", publicHash);
            var retainedLength = CryptographyHelper.ByteArrayToString(new byte[] { Convert.ToByte(CryptographyHelper.GetHexBytes(retained).Length) });
            var bName = CryptographyHelper.ByteArrayToString(Encoding.ASCII.GetBytes(name));
            var bVal = CryptographyHelper.ByteArrayToString(Encoding.ASCII.GetBytes(val));
            //COULD ADD ADDRESS HERE AT A LATER STAGE
            var costedPrefix = string.Format("53{0}{1}{2}{3}6d75",
                            CryptographyHelper.ByteArrayToString(new byte[] { Convert.ToByte(bName.Length / 2) }),
                            bName,
                            CryptographyHelper.ByteArrayToString(new byte[] { Convert.ToByte(bVal.Length / 2) }),
                            bVal
                            ); //New:1;First:2;Update:3;NOP:4, hash, OP_2DROP OP_DUP OP_HASH160, destination, OP_EQUALVERIFY OP_CHECKS
            var costed = string.Format("76a914{0}88ac", publicHash);
            var costedLength = CryptographyHelper.ByteArrayToString(new byte[] { Convert.ToByte(CryptographyHelper.GetHexBytes(costed).Length) });
            var costedWithPrefix = costedPrefix + costed;
            var costedWithPrefixLength = CryptographyHelper.ByteArrayToString(new byte[] { Convert.ToByte(CryptographyHelper.GetHexBytes(costedPrefix + costed).Length) });

            string[] oldHashReversed = new string[2];
            string[] index = new string[2];
            string[] pubKey = new string[2];
            oldHashReversed[0] = CryptographyHelper.ByteArrayToString(((byte[])CryptographyHelper.GetHexBytes(oldHash)).Reverse().ToArray()); //Reverse required     
            index[0] = CryptographyHelper.ByteArrayToString(lenc.GetBytes(oldIndex));
            pubKey[0] = oldPubKey;
            oldHashReversed[1] = CryptographyHelper.ByteArrayToString(((byte[])CryptographyHelper.GetHexBytes(oldNameHash)).Reverse().ToArray()); //Reverse required     
            index[1] = CryptographyHelper.ByteArrayToString(lenc.GetBytes(oldNameIndex));
            pubKey[1] = oldNamePubKey;

            string signed = string.Empty;
            for (int i = 0; i < 2; i++)
            {
                string bsToSign = string.Empty;
                bsToSign += v;
                bsToSign += inputs;
                for (int j = 0; j < 2; j++)
                {

                    bsToSign += oldHashReversed[j] + index[j];
                    if (i == j)
                    {
                        var oldPubKeyLength = CryptographyHelper.ByteArrayToString(new byte[] { Convert.ToByte(CryptographyHelper.GetHexBytes(pubKey[i]).Length) });
                        bsToSign += oldPubKeyLength + pubKey[i];
                    }
                    else
                        bsToSign += "00"; //or 0
                    bsToSign += sequenced;
                }
                bsToSign += "02"; //Output Count
                bsToSign += retain;
                bsToSign += retainedLength;
                bsToSign += retained;
                bsToSign += cost;
                bsToSign += costedWithPrefixLength;
                bsToSign += costedWithPrefix;
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

        private static string CreateBuyTransaction(string publicKey, string privateKey, string name, string rand, double balance, string oldHash, string oldPubKey, int oldIndex)
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

        private static string GetTransactionID(string txHex)
        {
            return CryptographyHelper.ByteArrayToString(CryptographyHelper.Hash256(CryptographyHelper.Hash256(CryptographyHelper.GetHexBytes(txHex))).Reverse().ToArray());
        }

        public static dynamic GetBlocks()
        {
            return ExecuteCall("getblockcount", null).result.Value;
        }

        public static List<dynamic> GetPeers(bool skipServerLookup = true)
        {
            IPAddress destinationIP = null;
            if (!skipServerLookup)
            {
                try
                {
                    destinationIP = Dns.GetHostAddresses(ConstantsHelper.PROTOCOL_HOST_DEFAULT).FirstOrDefault();
                }
                catch { }
            }
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

        private static string CreateVersionMessage(IPAddress destinationIP=null, int? destinationPort=default(int?), IPAddress originIP=null, int? originPort=default(int?))
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

        private static dynamic ProcessBroadcastResponse(byte[] bytes)
        {

            dynamic result = new ExpandoObject();
            var lenc = new LittleEndianBitConverter();
            var benc = new BigEndianBitConverter();
            result.Magic = lenc.ToUInt32(bytes, 0);
            result.Command = Encoding.ASCII.GetString(bytes, 4, 12).Replace("\0", "");
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
                    for (; offset < payload.Length; offset += 30)
                    {
                        var address = new
                        {
                            Timestamp = lenc.ToUInt32(payload, offset),
                            Service = lenc.ToUInt64(payload, offset + 4),
                            IP = new IPAddress((long)lenc.ToUInt32(payload, offset + 24)),
                            Port = benc.ToUInt16(payload, offset + 28)
                        };
                        result.Addresses.Add(address);
                    }
                    break;
                case "inv":
                    result.Count = VarLength(payload, 0);
                    offset = VarOffset(payload, 0);
                    result.Inventory = new List<dynamic>();
                    for (; offset < payload.Length; offset += 36)
                    {
                        var inv = new
                        {
                            InventoryType = lenc.ToUInt32(payload, offset),
                            Hash = CryptographyHelper.ByteArrayToString(payload.Skip(offset + 4).Take(32).Reverse().ToArray())
                        };
                        result.Inventory.Add(inv);
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
                            //return CryptographyHelper.ByteArrayToString(DownloadSocket(socket)); //socket.Receive(bytes); //nothing received may take30 mins may return an inv?
                            return GetTransactionID(hex); //TODO CHECK
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

            //var tempg = ExecuteMethod(NexusCall.Describe, new
            //{
            //    FromAddress = ConstantsHelper.TRUSTED_ADDRESSES[1],
            //    Key = "d/gabboncha2",
            //    Value = "{tested:tested55}",
            //});

        }
    }
}
