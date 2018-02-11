

using System.Security.Cryptography;
using Utils;
using System;

namespace Crypto
{
    public class MacHelper : IMacHelper
    {
        public HMAC mac { get; set; }

        public MacHelper()
        {
            this.mac = null;
        }
        public void Init(MacAlgorithm algorithm, byte[] key)
        {
            Preconditions.CheckNotNull(algorithm);
            Preconditions.CheckNotNull(key);

            if (algorithm.keySizeBits != key.Length * 8)
            {
                string msg = String.Format("Expected symmetric key of size {0} bits. Got {1} bits",
                                           algorithm.keySizeBits,
                                           key.Length * 8);
                throw new CryptographicException(msg);
            }

            this.mac = algorithm.GetMacAlgorithm();
            this.mac.Key = key;
        }

        public byte[] GetMac(byte[] message)
        {
            Preconditions.CheckNotNull(message);

            return this.mac.ComputeHash(message, 0, message.Length);
        }

        public bool VerifyMac(byte[] message, byte[] mac)
        {
            Preconditions.CheckNotNull(message);
            Preconditions.CheckNotNull(mac);
            
            byte[] expectedMac = this.GetMac(message);
            if (expectedMac.Length != mac.Length)
            {
                return false;
            }

            int diff = 0;
            for(int i = 0; i < expectedMac.Length && i < mac.Length; ++i)
            {
                diff |= (int)expectedMac[i] - (int)mac[i];
            }
            return (diff == 0);
        }

    }
}