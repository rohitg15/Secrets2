
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
        public int maxSecretBytes { get;  }
        public int maxSecretIdBytes { get; }

        public int iterCount { get; set; }
        public IEncryptionHelper encHelper { get; set; }
        public IMacHelper macHelper { get; set; }
        public SecretsManager(IEncryptionHelper encHelper, IMacHelper macHelper, int iterCount = 1000)
        {
            this.encHelper = Preconditions.CheckNotNull(encHelper);
            this.macHelper = Preconditions.CheckNotNull(macHelper);

            this.maxSecretBytes = 1024 * 1024;
            this.maxSecretIdBytes = 1024;
            this.iterCount = iterCount;
        }
        public KeySet GetSessionKeys(ref string password, CryptoAlgorithms alg)
        {
            Preconditions.CheckNotNull(password);
            Preconditions.CheckNotNull(alg);

            int saltSizeBytes = alg.kdfAlg.saltSizeBytes;
            byte[] salt = new byte[saltSizeBytes];
            var csprng = RandomNumberGenerator.Create();
            csprng.GetBytes(salt);            

            return DeriveSessionKeys(ref password, alg, salt);
        }

        public KeySet DeriveSessionKeys(ref string password, CryptoAlgorithms alg, byte[] salt)
        {
            Preconditions.CheckNotNull(password);
            Preconditions.CheckNotNull(alg);
            Preconditions.CheckNotNull(salt);

            int saltSizeBytes = alg.kdfAlg.saltSizeBytes;
            int encSizeBytes = alg.encAlg.keySizeBytes;
            int macSizeBytes = alg.macAlg.keySizeBytes;
            int outputSizeBytes = encSizeBytes + macSizeBytes;
            if (saltSizeBytes != salt.Length)
            {
                throw new ArgumentException("DeriveSessionKeys", "Expected and actual sizes for the salt are different");
            }
            byte[] encKey = new byte[encSizeBytes];
            byte[] macKey = new byte[macSizeBytes];


            KeyDerivationPrf prf = alg.kdfAlg.prf;
            byte[] sessionKey = KeyDerivation.Pbkdf2(password, salt, prf, this.iterCount, outputSizeBytes);
            Buffer.BlockCopy(sessionKey, 0, encKey, 0, encSizeBytes);
            Buffer.BlockCopy(sessionKey, encSizeBytes, macKey, 0, macSizeBytes);
            return new KeySet(encKey, macKey, salt);
        
        }

        public byte[] GetCanonicalizedPayload(byte[] algs, byte[] salt, byte[] ivOrNonce, byte[] secretId, byte[] encSecret)
        {
            Preconditions.CheckNotNull(algs);
            Preconditions.CheckNotNull(salt);
            Preconditions.CheckNotNull(ivOrNonce);
            Preconditions.CheckNotNull(secretId);
            Preconditions.CheckNotNull(encSecret);

            byte[] payload = new byte[algs.Length + salt.Length + ivOrNonce.Length + secretId.Length + encSecret.Length];
            int start = 0;
            Buffer.BlockCopy(algs, 0, payload, start, algs.Length);
            start += algs.Length;
            Buffer.BlockCopy(salt, 0, payload, start, salt.Length);
            start += salt.Length;
            Buffer.BlockCopy(ivOrNonce, 0, payload, start, ivOrNonce.Length);
            start += ivOrNonce.Length;
            Buffer.BlockCopy(secretId, 0, payload, start, secretId.Length);
            start += secretId.Length;
            Buffer.BlockCopy(encSecret, 0, payload, start, encSecret.Length);
            return payload;
        }

        public Secret Protect(ref string password, CryptoAlgorithms alg, string secretId, byte[] secretBytes, string tag = "Default")
        {
           Preconditions.CheckNotNull(password);
           Preconditions.CheckNotNull(alg);
           Preconditions.CheckNotNull(secretId);
           Preconditions.CheckNotNull(secretBytes);
           
           if (secretId.Length > this.maxSecretIdBytes)
           {
               throw new ArgumentOutOfRangeException("secretId", "secret Id cannot exceed " + this.maxSecretIdBytes);
           }
           if (secretBytes.Length > this.maxSecretBytes)
           {
               throw new ArgumentOutOfRangeException("secretBytes", "secretBytes cannot exceed " + this.maxSecretBytes);
           }

           // Derive session keys to protect secret
           KeySet sessionKeys = this.GetSessionKeys(ref password, alg);
        
           // Generate unique IV (or Nonce) for this secret based on given encryption algorithm
           byte[] iv = new byte[alg.encAlg.blockSizeBytes];
           var csprng = RandomNumberGenerator.Create();
           csprng.GetBytes(iv);

           // Initialize cryptosystem
           this.encHelper.Init(alg.encAlg, sessionKeys.encryptionKey, iv);
           this.macHelper.Init(alg.macAlg, sessionKeys.validationKey);

           // encrypt secret
           byte[] ciphertext = this.encHelper.EncryptBytes(secretBytes);

           // integrity protect canonicalized payload from all the above data
           byte[] algs = new byte[3];
           algs[0] = alg.encAlg.algId;
           algs[1] = alg.macAlg.algId;
           algs[2] = alg.kdfAlg.algId;
           byte[] secretIdBytes = StringUtils.GetBytes(secretId);
           byte[] payload = this.GetCanonicalizedPayload(algs, sessionKeys.salt, iv, secretIdBytes, ciphertext);
           byte[] mac = this.macHelper.GetMac(payload);

           // Generate Secret object
           string b64AlgIds = StringUtils.GetBase64String(algs);
           string b64Mac = StringUtils.GetBase64String(mac);
           string b64EncryptedStr = StringUtils.GetBase64String(ciphertext);
           string b64Iv = StringUtils.GetBase64String(iv);
           string b64Salt = StringUtils.GetBase64String(sessionKeys.salt);
           return new Secret(b64AlgIds, secretId, b64EncryptedStr, b64Salt, b64Iv, DateTime.UtcNow, tag, b64Mac);
        }

        public byte[] Unprotect(ref string password, Secret secret)
        {
            Preconditions.CheckNotNull(password);
            Preconditions.CheckNotNull(secret);

            byte[] algIds = StringUtils.GetBytesFromBase64(secret.b64AlgIds);
            byte[] salt = StringUtils.GetBytesFromBase64(secret.b64Salt);
            byte[] ivOrNonce = StringUtils.GetBytesFromBase64(secret.b64IvOrNonce);
            byte[] secretId = StringUtils.GetBytes(secret.secretId);
            byte[] ciphertext = StringUtils.GetBytesFromBase64(secret.b64EncryptedSecret);
            byte[] expMac = StringUtils.GetBytesFromBase64(secret.b64Mac);

            
            // Derive potential session keys from given data
            CryptoAlgorithms cryptoAlg = CryptoAlgorithms.InitFromAlgId(algIds);
            KeySet sessionKeys = DeriveSessionKeys(ref password, cryptoAlg, salt);

            // check integrity first
            byte[] payload = GetCanonicalizedPayload(algIds, salt, ivOrNonce, secretId, ciphertext);
            this.macHelper.Init(cryptoAlg.macAlg, sessionKeys.validationKey);
            
            if (this.macHelper.VerifyMac(payload, expMac) == false)
            {
                throw new ApplicationException("Invalid Signature!");
            }

            this.encHelper.Init(cryptoAlg.encAlg, sessionKeys.encryptionKey, ivOrNonce);
            byte[] secretBytes = this.encHelper.DecryptBytes(ciphertext);
            return secretBytes;
        }
    }
}