using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Pkcs;
using CNX.Shared.Models;
using ImpromptuInterface;
using ImpromptuInterface.Dynamic;
using ProtoBuf;
using Newtonsoft.Json;
using System.Dynamic;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1;

namespace CNX.Shared.Helpers
{
    public static class CryptographyHelper
    {
        private static readonly SecureRandom Random = new SecureRandom();

        public static string GenerateKey(int bitLength)
        {
            var key = new byte[bitLength / 8];
            Random.NextBytes(key);
            return Convert.ToBase64String(key);
        }

        public static void GenerateKeys(out string forPubKey, out string forPrivKey)
        {
            GenerateKeys(out forPubKey, out forPrivKey, 2048, 65537, 80);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="forPubKey"></param>
        /// <param name="forPrivKey"></param>
        /// <param name="keyStrength">1024, 2048,4096</param>
        /// <param name="exponent">Typically a fermat number 3, 5, 17, 257, 65537, 4294967297, 18446744073709551617,</param>
        /// <param name="certaninty">Should be 80 or higher depending on Key strength number (exponent)</param>
        public static void GenerateKeys(out string forPubKey, out string forPrivKey, int keyStrength, int exponent, int certaninty)
        {
            // Create key
            RsaKeyPairGenerator generator = new RsaKeyPairGenerator();

            /*
             * This value should be a Fermat number. 0x10001 (F4) is current recommended value. 3 (F1) is known to be safe also.
             * 3, 5, 17, 257, 65537, 4294967297, 18446744073709551617,
             * 
             * Practically speaking, Windows does not tolerate public exponents which do not fit in a 32-bit unsigned integer. Using e=3 or e=65537 works "everywhere". 
             */
            BigInteger exponentBigInt = new BigInteger(exponent.ToString());

            var param = new RsaKeyGenerationParameters(
                exponentBigInt, // new BigInteger("10001", 16)  publicExponent
                new SecureRandom(),  // SecureRandom.getInstance("SHA1PRNG"),//prng
                keyStrength, //strength
                certaninty);//certainty
            generator.Init(param);
            AsymmetricCipherKeyPair keyPair = generator.GenerateKeyPair();

            // Save to export format
            SubjectPublicKeyInfo info = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public);
            byte[] ret = info.GetEncoded();
            forPubKey = Convert.ToBase64String(ret);

            //  EncryptedPrivateKeyInfo asdf = EncryptedPrivateKeyInfoFactory.CreateEncryptedPrivateKeyInfo(
            //    DerObjectIdentifier.Ber,,,keyPair.Private);

            //TextWriter textWriter = new StringWriter();
            //PemWriter pemWriter = new PemWriter(textWriter);
            //pemWriter.WriteObject(keyPair);
            //pemWriter.Writer.Flush();
            //string ret2 = textWriter.ToString();

            //// demonstration: how to serialise option 1
            //TextReader tr = new StringReader(ret2);
            //PemReader read = new PemReader(tr);
            //AsymmetricCipherKeyPair something = (AsymmetricCipherKeyPair)read.ReadObject();

            //// demonstration: how to serialise option 2 (don't know how to deserailize)
            //PrivateKeyInfo pKinfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private);
            //byte[] privRet = pKinfo.GetEncoded();
            //string forPrivKey2Test = Convert.ToBase64String(privRet);

            PrivateKeyInfo pKinfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private);
            byte[] privRet = pKinfo.GetEncoded();
            string forPrivKey2Test = Convert.ToBase64String(privRet);

            forPrivKey = forPrivKey2Test;
        }


        public static void GenerateKeys(out string forPubKey, out string forPrivKey, out string address, AddressFamily? family = null, string prefix=null)
        {
            if (prefix == null)
                prefix = string.Empty;

            ECKeyPairGenerator gen = new ECKeyPairGenerator("ECDSA");
            Org.BouncyCastle.Asn1.X9.X9ECParameters ecp = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("secp256k1");
            ECDomainParameters ecSpec = new ECDomainParameters(ecp.Curve, ecp.G, ecp.N, ecp.H, ecp.GetSeed());


            SecureRandom secureRandom = new SecureRandom();
            ECKeyGenerationParameters ecgp = new ECKeyGenerationParameters(ecSpec, secureRandom);
            gen.Init(ecgp);

            AsymmetricCipherKeyPair keyPair = gen.GenerateKeyPair();
            //Stick to Base58 Encoding As Per Family Networks
            ECPrivateKeyParameters priv = (ECPrivateKeyParameters)keyPair.Private;
            while (true)
            {
                byte[] hexpriv = priv.D.ToByteArrayUnsigned();
                forPrivKey = ByteArrayToString(hexpriv);
                forPubKey = forPrivKey.ConvertPrivateToPublic();
                address = forPubKey.ConvertPublicHexToHash().ConvertPublicHashToAddress(family);

                if (address.Substring(1, prefix.Length) == prefix)
                    return;
                else
                    priv = new ECPrivateKeyParameters(priv.D.Add(new BigInteger(1, new byte[] { 0x01 })), ecSpec);
            }

        }


        public static byte[] SignWithPrivateKey(this string data, string privateKey)
        {
            RSACryptoServiceProvider rsa;

            // Private key
            var kparam = PrivateKeyFactory.CreateKey(Convert.FromBase64String(privateKey));
            RSAParameters pv = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)kparam);
            rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(pv);

          
            // compute sha1 hash of the data
            var sha = new SHA1CryptoServiceProvider();
            byte[] hash = sha.ComputeHash(Encoding.ASCII.GetBytes(data));

            // actually compute the signature of the SHA1 hash of the data
            var sig = rsa.SignHash(hash, CryptoConfig.MapNameToOID("SHA1"));

            return sig;
        }

        public static ECPrivateKeyParameters ConvertPrivateToParameters(string privateKey)
        {
            BigInteger biPrivateKey = new BigInteger(1, ValidateAndGetHexPrivateKey(privateKey).Skip(1).ToArray());
            Org.BouncyCastle.Asn1.X9.X9ECParameters ecP = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("secp256k1");
            ECDomainParameters ecSpec = new ECDomainParameters(ecP.Curve, ecP.G, ecP.N, ecP.H, ecP.GetSeed());
            return new ECPrivateKeyParameters(biPrivateKey, ecSpec);
        }
        public static ECPublicKeyParameters ConvertPublicToParameters(string publicKey)
        {
            Org.BouncyCastle.Asn1.X9.X9ECParameters ecP = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("secp256k1");
            ECDomainParameters ecSpec = new ECDomainParameters(ecP.Curve, ecP.G, ecP.N, ecP.H, ecP.GetSeed());
            var pubBytes = ValidateAndGetHexPublicKey(publicKey).Skip(1).ToArray();
            var c = (FpCurve)ecP.Curve;
            ECFieldElement x = c.FromBigInteger(new BigInteger(1, pubBytes.Take(32).ToArray()));
            ECFieldElement y = c.FromBigInteger(new BigInteger(1, pubBytes.Skip(32).ToArray()));
            ECPoint dd = new FpPoint(c, x, y);
            return new ECPublicKeyParameters(dd, ecSpec);
        }

        public static byte[] SignWithElliptical(this string data, string privateKey)
        {
            ISigner signer = SignerUtilities.GetSigner("NONEwithECDSA");
            signer.Init(true, ConvertPrivateToParameters(privateKey));
            var bytes = Encoding.ASCII.GetBytes(data);
            signer.BlockUpdate(bytes, 0, bytes.Length);
            return signer.GenerateSignature();
        }

        public static byte[] SignWithElliptical(this byte[] data, string privateKey)
        {
            ISigner signer = SignerUtilities.GetSigner("NONEwithECDSA"); //SHA-256withECDSA
            signer.Init(true, ConvertPrivateToParameters(privateKey));
            signer.BlockUpdate(data, 0, data.Length);            
            var sig = signer.GenerateSignature();
            
            
            //var seq = (DerSequence)DerSequence.FromByteArray(sig);
            //var derIntR = ((DerInteger)seq.GetObjectAt(0)).Value.ToByteArrayUnsigned();
            //var derIntS = ((DerInteger)seq.GetObjectAt(1)).Value.ToByteArrayUnsigned();
            //BigInteger my_r = derIntR.Value..getValue();
            //BigInteger my_s = derIntS.getValue(); 
            return sig;            
            
        }

        public static bool VerifyElliptical(this byte[] data, string publicKey, byte[] signature)
        {
            ISigner signer = SignerUtilities.GetSigner("NONEwithECDSA");
            signer.Init(false, ConvertPublicToParameters(publicKey));
            signer.BlockUpdate(data, 0, data.Length);
            return signer.VerifySignature(signature);
        }

        public static bool VerifyElliptical(this string data, string publicKey, byte[] signature)
        {
            ISigner signer = SignerUtilities.GetSigner("NONEwithECDSA");            
            signer.Init(false, ConvertPublicToParameters(publicKey));
            var bytes = Encoding.ASCII.GetBytes(data);
            signer.BlockUpdate(bytes, 0, bytes.Length);
            return signer.VerifySignature(signature);
        }


        public static string DecryptElliptical(this string data, string publicKey, string myPrivateKey)
        {

            var d = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
            var e = new byte[] { 8, 7, 6, 5, 4, 3, 2, 1 };
            var p = new IesWithCipherParameters(d, e, 64, 128);

            IesEngine e2 = new IesEngine(
               new ECDHBasicAgreement(),
               new Kdf2BytesGenerator(new Sha1Digest()),
               new HMac(new Sha256Digest()), // #1 
               new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesEngine()))); // #6 
            e2.Init(false, ConvertPrivateToParameters(myPrivateKey), ConvertPublicToParameters(publicKey), p);
            var bytes = Convert.FromBase64String(data);
            return Encoding.UTF8.GetString(e2.ProcessBlock(bytes, 0, bytes.Length));            
        }

        public static string EncryptElliptical(this string data, string publicKey, string myPrivateKey)
        {

            IesEngine e1 = new IesEngine(
                new ECDHBasicAgreement(),
                new Kdf2BytesGenerator(new Sha1Digest()),
                new HMac(new Sha256Digest()), // #1 
                new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesEngine()))); // #6 
            var d = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
            var e = new byte[] { 8, 7, 6, 5, 4, 3, 2, 1 };
            var p = new IesWithCipherParameters(d, e, 64, 128);

            //IesWithCipherParameters parameterSpec = new IesWithCipherParameters(null, null, 256, 256);
            e1.Init(true, ConvertPrivateToParameters(myPrivateKey), ConvertPublicToParameters(publicKey), p);
            byte[] bytes = Encoding.UTF8.GetBytes(data);
            return Convert.ToBase64String(e1.ProcessBlock(bytes, 0, bytes.Length));
            ////BufferedIesCipher c1 = new BufferedIesCipher(e1);
            ////c1.engineSetMode("DHAES"); 
            ////c1.Init(true, keyParameters);
            ////var ciphertext = c1.DoFinal(Encoding.UTF8.GetBytes(@"test"));

            //IesEngine e2 = new IesEngine(
            //   new ECDHBasicAgreement(),
            //   new Kdf2BytesGenerator(new Sha1Digest()),
            //   new HMac(new Sha256Digest()), // #1 
            //   new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesEngine()))); // #6 
            //e2.Init(false, privateParameters, publicParameters, p);
            //var result = e2.ProcessBlock(ct, 0, ct.Length);
            //var text = Encoding.UTF8.GetString(result);
            ////IesParameterSpec parameterSpec = new IESParameterSpec(null, null, macKeySize, cipherKeySize);

            ////byte[] pubaddr = new byte[65];
            ////byte[] Y = dd.Y.ToBigInteger().ToByteArray();
            ////Array.Copy(Y, 0, pubaddr, 64 - Y.Length + 1, Y.Length);
            ////byte[] X = dd.X.ToBigInteger().ToByteArray();
            ////Array.Copy(X, 0, pubaddr, 32 - X.Length + 1, X.Length);
            ////pubaddr[0] = 4;

            //return null;
        }

        public static string Encrypt(this string data, string publicKey)
        {
            //RsaKeyParameters privParameters = new RsaPrivateCrtKeyParameters(mod, pubExp, privExp, p, q, pExp, qExp, crtCoef);
            //RsaKeyParameters pubParameters = new RsaKeyParameters(false, mod, pubExp);
            //IAsymmetricBlockCipher eng = new Pkcs1Encoding(new RsaEngine());
            RSACryptoServiceProvider rsa;
            var kparam = PublicKeyFactory.CreateKey(Convert.FromBase64String(publicKey));
            RSAParameters pu = DotNetUtilities.ToRSAParameters((RsaKeyParameters)kparam);
            rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(pu);
            var encdata = rsa.Encrypt(Encoding.UTF8.GetBytes(data), true);
            return Convert.ToBase64String(encdata);
            
        }

        public static string Encrypt<T>(this T data, string publicKey)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                RSACryptoServiceProvider rsa;
                var kparam = PublicKeyFactory.CreateKey(Convert.FromBase64String(publicKey));
                RSAParameters pu = DotNetUtilities.ToRSAParameters((RsaKeyParameters)kparam);
                rsa = new RSACryptoServiceProvider();
                rsa.ImportParameters(pu);
                Serializer.Serialize<T>(ms, data);
                ms.Position = 0;
                byte[] msg;
                using (BinaryReader br = new BinaryReader(ms))
                    msg = br.ReadBytes((int)ms.Length);
                var encdata = rsa.Encrypt(msg, true);
                return Convert.ToBase64String(encdata);
            }
        }

        public static string EncryptSymmetric<T>(this T data, string symmetricKey, string initialisationVector)
        {            
            var keyParameter = new KeyParameter(Convert.FromBase64String(symmetricKey));
            const int macSize = 128;
            var nonce = new byte[128 / 8];
            nonce = Encoding.UTF8.GetBytes(initialisationVector).Take(nonce.Length).ToArray();
            var associatedText = new byte[] { };
            var cipher = new GcmBlockCipher(new AesFastEngine());
            var parameters = new AeadParameters(keyParameter, macSize, nonce, associatedText);
            cipher.Init(true, parameters);          
            using (MemoryStream ms = new MemoryStream())
            {
                Serializer.Serialize<T>(ms, data);
                ms.Position = 0;
                byte[] msg;
                using (BinaryReader br = new BinaryReader(ms))
                    msg = br.ReadBytes((int)ms.Length);
                var encdata = new byte[cipher.GetOutputSize(msg.Length)];
                var len = cipher.ProcessBytes(msg, 0, msg.Length, encdata, 0);
                cipher.DoFinal(encdata, len); 
                return Convert.ToBase64String(encdata);
            }
           
        }

        public static string EncryptSymmetric(this string data, string symmetricKey, string initialisationVector)
        {
            var keyParameter = new KeyParameter(Convert.FromBase64String(symmetricKey));
            const int macSize = 128;
            var nonce = new byte[128 / 8];            
            nonce = Encoding.UTF8.GetBytes(initialisationVector).Take(nonce.Length).ToArray();
            var associatedText = new byte[] { };
            var cipher = new GcmBlockCipher(new AesFastEngine());
            var parameters = new AeadParameters(keyParameter, macSize, nonce, associatedText);
            cipher.Init(true, parameters);
            var msg = Encoding.UTF8.GetBytes(data);
            var encdata = new byte[cipher.GetOutputSize(msg.Length)];
            var len = cipher.ProcessBytes(msg, 0, msg.Length, encdata, 0);
            cipher.DoFinal(encdata, len);
            return Convert.ToBase64String(encdata);            
        }

        public static string Decrypt(this string encrypted, string privateKey)
        {
            //RsaKeyParameters privParameters = new RsaPrivateCrtKeyParameters(mod, pubExp, privExp, p, q, pExp, qExp, crtCoef);
            //RsaKeyParameters pubParameters = new RsaKeyParameters(false, mod, pubExp);
            //IAsymmetricBlockCipher eng = new Pkcs1Encoding(new RsaEngine());
            RSACryptoServiceProvider rsa;
            var kparam = PrivateKeyFactory.CreateKey(Convert.FromBase64String(privateKey));
            RSAParameters pu = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)kparam);
            rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(pu);
            var result = rsa.Decrypt(Convert.FromBase64String(encrypted), true);
            return Encoding.UTF8.GetString(result);

        }

        public static T Decrypt<T>(this string encrypted, string privateKey)
        {
            //RsaKeyParameters privParameters = new RsaPrivateCrtKeyParameters(mod, pubExp, privExp, p, q, pExp, qExp, crtCoef);
            //RsaKeyParameters pubParameters = new RsaKeyParameters(false, mod, pubExp);
            //IAsymmetricBlockCipher eng = new Pkcs1Encoding(new RsaEngine());
            RSACryptoServiceProvider rsa;
            var kparam = PrivateKeyFactory.CreateKey(Convert.FromBase64String(privateKey));
            RSAParameters pu = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)kparam);
            rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(pu);
            using (MemoryStream ms = new MemoryStream(rsa.Decrypt(Convert.FromBase64String(encrypted), true)))
                return Serializer.Deserialize<T>(ms);

        }

        public static T DecryptSymmetric<T>(this string encrypted, string symmetricKey, string initialisationVector)
        {
            var keyParameter = new KeyParameter(Convert.FromBase64String(symmetricKey));
            const int macSize = 128;
            var nonce = new byte[128 / 8];
            nonce = Encoding.UTF8.GetBytes(initialisationVector).Take(nonce.Length).ToArray(); 
            var encdata = Convert.FromBase64String(encrypted);     
            var associatedText = new byte[] { };
            var cipher = new GcmBlockCipher(new AesFastEngine());
            var parameters = new AeadParameters(keyParameter, macSize, nonce, associatedText);
            cipher.Init(false, parameters);
            var msg = new byte[cipher.GetOutputSize(encdata.Length)];
            var len = cipher.ProcessBytes(encdata, 0, encdata.Length, msg, 0);
            cipher.DoFinal(msg, len);
            using (MemoryStream ms = new MemoryStream(msg, false))
                return Serializer.Deserialize<T>(ms);            
        }


        public static string DecryptSymmetric(this string encrypted, string symmetricKey, string initialisationVector)
        {
            var keyParameter = new KeyParameter(Convert.FromBase64String(symmetricKey));
            const int macSize = 128;
            var nonce = new byte[128 / 8];
            nonce = Encoding.UTF8.GetBytes(initialisationVector).Take(nonce.Length).ToArray(); 
            var encdata = Convert.FromBase64String(encrypted);
            var associatedText = new byte[] { };
            var cipher = new GcmBlockCipher(new AesFastEngine());
            var parameters = new AeadParameters(keyParameter, macSize, nonce, associatedText);
            cipher.Init(false, parameters);
            var msg = new byte[cipher.GetOutputSize(encdata.Length)];
            var len = cipher.ProcessBytes(encdata, 0, encdata.Length, msg, 0); 
            cipher.DoFinal(msg, len);
            return Encoding.UTF8.GetString(msg);            
        }

        public static string SignAndSerialize<T>(this T m, string privateKey)
        {
            ISignature sig = m as ISignature;
            if (sig == null)
                throw new Exception("Can't sign and serialize object type.");
            if (!sig.AuthorisedByCompanyID.HasValue || sig.AuthorisedByCompanyID == default(Guid))
                throw new Exception("Can't sign and serialize without authority");
            sig.Signature = Convert.ToBase64String(JsonConvert.SerializeObject(m).SignWithPrivateKey(privateKey));
            return JsonConvert.SerializeObject(m);
        }

        public static bool Verify(this string data, string publicKey, byte[] signature)
        {
            RSACryptoServiceProvider rsa;
            // Public key
            var kparam = PublicKeyFactory.CreateKey(Convert.FromBase64String(publicKey));
            RSAParameters pu = DotNetUtilities.ToRSAParameters((RsaKeyParameters)kparam);
            rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(pu);

            // compute sha1 hash of the data
            var sha = new SHA1CryptoServiceProvider();
            byte[] hash = sha.ComputeHash(Encoding.ASCII.GetBytes(data));

            // This always returns false
            return rsa.VerifyHash(hash, CryptoConfig.MapNameToOID("SHA1"), signature);
        }

        public static T VerifyAndDeserialize<T>(this string data, string publicKey)
        {
            object m = JsonConvert.DeserializeObject<ExpandoObject>(data);
            ISignature sig = m.ActLike<ISignature>();
            if (sig == null)
                throw new System.Security.SecurityException("Could not verify integrity of request. Not a secure response.");
            var signature = sig.Signature;
            sig.Signature = null;
            var original = JsonConvert.SerializeObject(m);
            if (!Verify(original, publicKey, Convert.FromBase64String(signature)))
                throw new System.Security.SecurityException("Object does not contain a valid signature.");
            return JsonConvert.DeserializeObject<T>(data);
        }

        public static bool Verify<T>(this T m, string publicKey)
        {
            ISignature sig = m.ActLike<ISignature>();
            if (sig == null)
                throw new System.Security.SecurityException("Could not verify integrity of request. Not a secure response.");
            var signature = sig.Signature;
            sig.Signature = null;
            var original = JsonConvert.SerializeObject(m);
            if (!Verify(original, publicKey, Convert.FromBase64String(signature)))
                throw new System.Security.SecurityException("Object does not contain a valid signature.");
            return true;
        }

        public static bool CheckNonce(this string nonceString)
        {
            if (string.IsNullOrWhiteSpace(nonceString))
                return false;
            Guid nonce;
            if (!Guid.TryParse(nonceString, out nonce))
                return false;
            DateTime nonced = nonce.GetDate();
            if (nonced > DateTime.UtcNow.AddMinutes(15) || nonced < DateTime.Now.AddMinutes(-15))
                return false;
            return true;
        }


        //Following code from https://bitcointalk.org/index.php?topic=25141.0
       
        public static byte[] Base58ToByteArray(string base58)
        {

            Org.BouncyCastle.Math.BigInteger bi2 = new Org.BouncyCastle.Math.BigInteger("0");
            string b58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

            bool IgnoreChecksum = false;

            foreach (char c in base58)
            {
                if (b58.IndexOf(c) != -1)
                {
                    bi2 = bi2.Multiply(new Org.BouncyCastle.Math.BigInteger("58"));
                    bi2 = bi2.Add(new Org.BouncyCastle.Math.BigInteger(b58.IndexOf(c).ToString()));
                }
                else if (c == '?')
                {
                    IgnoreChecksum = true;
                }
                else
                {
                    return null;
                }
            }

            byte[] bb = bi2.ToByteArrayUnsigned();

            // interpret leading '1's as leading zero bytes
            foreach (char c in base58)
            {
                if (c != '1') break;
                byte[] bbb = new byte[bb.Length + 1];
                Array.Copy(bb, 0, bbb, 1, bb.Length);
                bb = bbb;
            }

            if (bb.Length < 4) return null;

            if (IgnoreChecksum == false)
            {
                SHA256CryptoServiceProvider sha256 = new SHA256CryptoServiceProvider();
                byte[] checksum = sha256.ComputeHash(bb, 0, bb.Length - 4);
                checksum = sha256.ComputeHash(checksum);
                for (int i = 0; i < 4; i++)
                {
                    if (checksum[i] != bb[bb.Length - 4 + i]) return null;
                }
            }

            byte[] rv = new byte[bb.Length - 4];
            Array.Copy(bb, 0, rv, 0, bb.Length - 4);
            return rv;
        }

        public static string ByteArrayToString(byte[] ba)
        {
            return ByteArrayToString(ba, 0, ba.Length);
        }

        public static string ByteArrayToString(byte[] ba, int offset, int count)
        {
            string rv = "";
            int usedcount = 0;
            for (int i = offset; usedcount < count; i++, usedcount++)
            {
                rv += String.Format("{0:X2}", ba[i]);
            }
            return rv;
        }

        public static string ByteArrayToBase58(byte[] ba)
        {
            Org.BouncyCastle.Math.BigInteger addrremain = new Org.BouncyCastle.Math.BigInteger(1, ba);

            Org.BouncyCastle.Math.BigInteger big0 = new Org.BouncyCastle.Math.BigInteger("0");
            Org.BouncyCastle.Math.BigInteger big58 = new Org.BouncyCastle.Math.BigInteger("58");

            string b58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

            string rv = "";

            while (addrremain.CompareTo(big0) > 0)
            {
                int d = Convert.ToInt32(addrremain.Mod(big58).ToString());
                addrremain = addrremain.Divide(big58);
                rv = b58.Substring(d, 1) + rv;
            }

            // handle leading zeroes
            foreach (byte b in ba)
            {
                if (b != 0) break;
                rv = "1" + rv;

            }
            return rv;
        }


        public static string ByteArrayToBase58Check(byte[] ba)
        {

            byte[] bb = new byte[ba.Length + 4];
            Array.Copy(ba, bb, ba.Length);
            SHA256CryptoServiceProvider sha256 = new SHA256CryptoServiceProvider();
            byte[] thehash = sha256.ComputeHash(ba);
            thehash = sha256.ComputeHash(thehash);
            for (int i = 0; i < 4; i++) bb[ba.Length + i] = thehash[i];
            return ByteArrayToBase58(bb);
        }

        public static byte[] GetHexBytes(string source, int minimum)
        {
            byte[] hex = GetHexBytes(source);
            if (hex == null) return null;
            // assume leading zeroes if we're short a few bytes
            if (hex.Length > (minimum - 6) && hex.Length < minimum)
            {
                byte[] hex2 = new byte[minimum];
                Array.Copy(hex, 0, hex2, minimum - hex.Length, hex.Length);
                hex = hex2;
            }
            // clip off one overhanging leading zero if present
            if (hex.Length == minimum + 1 && hex[0] == 0)
            {
                byte[] hex2 = new byte[minimum];
                Array.Copy(hex, 1, hex2, 0, minimum);
                hex = hex2;

            }

            return hex;
        }

        public static byte[] GetHexBytes(ulong[] source)
        {
            byte[] result = new byte[source.Length * sizeof(ulong)];
            Buffer.BlockCopy(source, 0, result, 0, result.Length);
            return result;
        }

        public static byte[] GetHexBytes(uint[] source)
        {
            byte[] result = new byte[source.Length * sizeof(uint)];
            Buffer.BlockCopy(source, 0, result, 0, result.Length);
            return result;
        }

        public static byte[] GetHexBytes(string source)
        {


            List<byte> bytes = new List<byte>();
            // copy s into ss, adding spaces between each byte
            string s = source;
            string ss = "";
            int currentbytelength = 0;
            foreach (char c in s.ToCharArray())
            {
                if (c == ' ')
                {
                    currentbytelength = 0;
                }
                else
                {
                    currentbytelength++;
                    if (currentbytelength == 3)
                    {
                        currentbytelength = 1;
                        ss += ' ';
                    }
                }
                ss += c;
            }

            foreach (string b in ss.Split(' '))
            {
                int v = 0;
                if (b.Trim() == "") continue;
                foreach (char c in b.ToCharArray())
                {
                    if (c >= '0' && c <= '9')
                    {
                        v *= 16;
                        v += (c - '0');

                    }
                    else if (c >= 'a' && c <= 'f')
                    {
                        v *= 16;
                        v += (c - 'a' + 10);
                    }
                    else if (c >= 'A' && c <= 'F')
                    {
                        v *= 16;
                        v += (c - 'A' + 10);
                    }

                }
                v &= 0xff;
                bytes.Add((byte)v);
            }
            return bytes.ToArray();
        }

        public static byte[] ValidateAndGetHexPrivateKey(this string privateHex, byte leadingbyte = 0x00)
        {
            byte[] hex = GetHexBytes(privateHex, 32);

            if (hex == null || hex.Length < 32 || hex.Length > 33)
            {
                throw new Exception("Hex is not 32 or 33 bytes.");
                //return null;
            }

            // if leading 00, change it to 0x80
            if (hex.Length == 33)
            {
                if (hex[0] == 0 || hex[0] == 0x80)
                {
                    hex[0] = 0x80;
                }
                else
                {
                    throw new Exception("Not a valid private key");
                    //return null;
                }
            }

            // add 0x80 byte if not present
            if (hex.Length == 32)
            {
                byte[] hex2 = new byte[33];
                Array.Copy(hex, 0, hex2, 1, 32);
                hex2[0] = 0x80;
                hex = hex2;
            }

            hex[0] = leadingbyte;
            return hex;

        }


        public static byte[] ValidateAndGetHexPublicKey(this string publicHex)
        {
            byte[] hex = GetHexBytes(publicHex, 64);

            if (hex == null || hex.Length < 64 || hex.Length > 65)
            {
                throw new Exception("Hex is not 64 or 65 bytes.");
                //return null;
            }

            // if leading 00, change it to 0x80
            if (hex.Length == 65)
            {
                if (hex[0] == 0 || hex[0] == 4)
                {
                    hex[0] = 4;
                }
                else
                {
                    throw new Exception("Not a valid public key");
                    //return null;
                }
            }

            // add 0x80 byte if not present
            if (hex.Length == 64)
            {
                byte[] hex2 = new byte[65];
                Array.Copy(hex, 0, hex2, 1, 64);
                hex2[0] = 4;
                hex = hex2;
            }
            return hex;
        }

        public static byte[] ValidateAndGetHexPublicHash(string publicHash)
        {
            byte[] hex = GetHexBytes(publicHash, 20);

            if (hex == null || hex.Length != 20)
            {
                throw new Exception("Hex is not 20 bytes.");
                //return null;
            }
            return hex;
        }

        
        public static string ConvertPrivateHexToWIF(this string privateHex)
        {
            byte[] hex = ValidateAndGetHexPrivateKey(privateHex, 0x80);
            if (hex == null)
                throw new Exception("Could not validate private key");
            return ByteArrayToBase58Check(hex);
        }

        public static string Correct(string btcaddr)
        {

            int btcaddrlen = btcaddr.Length;
            string b58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

            for (int i = 0; i < btcaddrlen; i++)
            {
                for (int j = 0; j < 58; j++)
                {
                    string attempt = btcaddr.Substring(0, i) + b58.Substring(j, 1) + btcaddr.Substring(i + 1);
                    byte[] bytes = Base58ToByteArray(attempt);
                    if (bytes != null)
                    {                        
                        return attempt; //Success
                    }
                }
            }
            return btcaddr;
        }


        public static string ConvertHexToBase58(this string hex)
        {
            return ByteArrayToBase58(GetHexBytes(hex));            
        }

        public static string ConvertBase58ToHex(this string address)
        {
            return ByteArrayToString(Base58ToByteArray(address));
        }   

              
        public static string ConvertPrivateWIFToHex(this string privateWIF)
        {
            byte[] hex = Base58ToByteArray(privateWIF);
            if (hex == null)
            {
                int L = privateWIF.Length;
                if (L >= 50 && L <= 52)
                {
                    hex = Base58ToByteArray(Correct(privateWIF)); //Do correction
                }
                else
                {
                    throw new Exception("WIF private key is not valid.");
                }
            }
            if (hex.Length != 33)
            {
                throw new Exception("WIF private key is not valid (wrong byte count, should be 33, was " + hex.Length + ")");
            }
            return ByteArrayToString(hex, 1, 32);
        }

        public static string ConvertPrivateToPublic(this string privateHex)
        {
            byte[] hex = ValidateAndGetHexPrivateKey(privateHex, 0x00);
            if (hex == null) throw new Exception("Could not convert private key to public key. Bad private key.");
            var ps = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("secp256k1");
            Org.BouncyCastle.Math.BigInteger Db = new Org.BouncyCastle.Math.BigInteger(1, hex.Skip(1).ToArray());
            ECPoint dd = ps.G.Multiply(Db);

            byte[] pubaddr = new byte[65];
            byte[] Y = dd.Y.ToBigInteger().ToByteArray();
            Array.Copy(Y, 0, pubaddr, 64 - Y.Length + 1, Y.Length);
            byte[] X = dd.X.ToBigInteger().ToByteArray();
            Array.Copy(X, 0, pubaddr, 32 - X.Length + 1, X.Length);
            pubaddr[0] = 4;

            return ByteArrayToString(pubaddr);

        }

        public static string ConvertPublicHexToHash(this string publicHex)
        {
            byte[] hex = ValidateAndGetHexPublicKey(publicHex);
            if (hex == null) throw new Exception("Could not convert public key to hash. Bad public key."); 
            return ByteArrayToString(Hash160(hex));
        }

        public static byte[] Hash160(this byte[] hex)
        {
            SHA256CryptoServiceProvider sha256 = new SHA256CryptoServiceProvider();
            byte[] shaofpubkey = sha256.ComputeHash(hex);
            RIPEMD160 rip = System.Security.Cryptography.RIPEMD160.Create();
            return rip.ComputeHash(shaofpubkey);
        }

        public static byte[] Hash256(this byte[] hex)
        {
            SHA256CryptoServiceProvider sha256 = new SHA256CryptoServiceProvider();
            return sha256.ComputeHash(hex);
        }


        public enum AddressFamily {
            BTC,
            NMC,
            Test
        }

        public static string ConvertPublicHashToAddress(this string publicHash, AddressFamily? family = null)
        {
            byte[] hex = ValidateAndGetHexPublicHash(publicHash);
            if (hex == null) throw new Exception("Could not convert public hash to address. Bad public hash."); 

            byte[] hex2 = new byte[21];
            Array.Copy(hex, 0, hex2, 1, 20);

            int fam = 0; //BTC
            if (family != null)
            {
                if (family == AddressFamily.Test)
                    fam = 111;
                else if (family == AddressFamily.NMC)
                    fam = 52;
            }
            hex2[0] = (byte)(fam & 0xff);
            return ByteArrayToBase58Check(hex2);
        }

     
        public static string ConvertAddressToPublicHash(this string address)
        {
            byte[] hex = Base58ToByteArray(address);
            if (hex == null || hex.Length != 21)
            {
                int L = address.Length;
                if (L >= 33 && L <= 34)
                {
                    hex =  Base58ToByteArray(Correct(address)); //Correction
                }
                else
                {
                    throw new Exception("Address is not valid. (wrong byte count, should be 21). ");
                }
                
            }            
            return ByteArrayToString(hex, 1, 20);

        }

        public static void Test()
        {
            string npv, npu, nad;
            CryptographyHelper.GenerateKeys(out npu, out npv, out nad, AddressFamily.NMC,"C");

            string npv2, npu2, nad2;
            CryptographyHelper.GenerateKeys(out npu2, out npv2, out nad2);

            //npv2 = string.Join("", npv2.Take(3).ToArray()) + "5" + string.Join("", npv2.Skip(4).TakeWhile(f => true).ToArray());
            var rce = DecryptElliptical(EncryptElliptical("test me", npu, npv2), npu2, npv); //works

            var test = @"can you please sign this statement";
            var rse = VerifyElliptical(test, npu, SignWithElliptical(test, npv));

            string pv, pu;
            CryptographyHelper.GenerateKeys(out pu, out pv);
            var s = CryptographyHelper.Encrypt("asdad", pu);
            var y = CryptographyHelper.Decrypt(s, pv);
            var x = CryptographyHelper.SignWithPrivateKey("y", pv);
            var session = Convert.ToBase64String(x);
            var z = CryptographyHelper.Verify("yy", pu, x);
            //Console.WriteLine("Done.");
            //Console.ReadLine();

            var sr = new CNX.Shared.Models.SessionRequest { CompanyID = Guid.NewGuid() };
            var nonce = GuidHelper.Nonce;
            var sk = CryptographyHelper.GenerateKey(256);
            var enc = CryptographyHelper.EncryptSymmetric<CNX.Shared.Models.SessionRequest>(sr, sk, nonce);
            var dev = CryptographyHelper.DecryptSymmetric<CNX.Shared.Models.SessionRequest>(enc, sk, nonce);

           
        }

    }
}
