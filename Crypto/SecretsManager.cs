
using Models;
using System.Collections.Generic;
using Utils;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System.Security.Cryptography;
using System;

namespace Crypto
{
    public class SecretsManager
    {
        public CryptoAlgorithms alg { get; set; }

        public SecretsManager(CryptoAlgorithms alg)
        {
            this.alg = Preconditions.CheckNotNull(alg);
        }
        public KeySet GetKeys(ref string password)
        {
            int saltSizeBytes = this.alg.kdfAlg.saltSizeBytes;
            byte[]  salt = new byte[saltSizeBytes];
            var csprng = RandomNumberGenerator.Create();
            csprng.GetBytes(salt);

            int encSizeBytes = this.alg.encAlg.keySizeBits / 8;
            int macSizeBytes = this.alg.macAlg.keySizeBits / 8;
            int outputSizeBytes = encSizeBytes + macSizeBytes;

            KeyDerivationPrf prf = this.alg.kdfAlg.prf;
            int iterCount = this.alg.kdfAlg.iterCount;
            
            byte[] sessionKey = KeyDerivation.Pbkdf2(password, salt, prf, iterCount, outputSizeBytes);
            byte[] encKey = new byte[encSizeBytes];
            byte[] macKey = new byte[macSizeBytes];
            Buffer.BlockCopy(sessionKey, 0, encKey, 0, encSizeBytes);
            Buffer.BlockCopy(sessionKey, encSizeBytes, macKey, 0, macSizeBytes);
            return new KeySet(encKey, macKey);
        }

        public Secret protect(ref string password, byte[] secretBytes)
        {
            return null;
        }

        public byte[] unprotect(Secret secret)
        {
            return null;
        }
    }
}