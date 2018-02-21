using System;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Utils;

namespace Crypto
{


    public class CryptoAlgorithms
    {
        public EncryptionAlgorithm encAlg { get; set; }
        public MacAlgorithm macAlg { get; set; }
        public KdfAlgorithm kdfAlg { get; set; }

        public CryptoAlgorithms(EncryptionAlgorithm enc, MacAlgorithm mac, KdfAlgorithm kdf)
        {
            this.encAlg = Preconditions.CheckNotNull(enc);
            this.macAlg = Preconditions.CheckNotNull(mac);
            this.kdfAlg = Preconditions.CheckNotNull(kdf);
        }

        public static CryptoAlgorithms InitFromAlgId(byte[] algIds)
        {
            Preconditions.CheckNotNull(algIds);
            if (algIds.Length != 3)
            {
                throw new ArgumentOutOfRangeException("InitFromAlgId", "Expected 3 bytes to denote the 3 algorithms");
            }

            EncryptionAlgorithmType encAlgType = EncryptionAlgorithmType.AES_CBC;
            MacAlgorithmType macAlgType = MacAlgorithmType.HMAC_SHA512;
            KeyDerivationPrf kdfPrf = KeyDerivationPrf.HMACSHA512;
            byte encAlgId = algIds[0], macAlgId = algIds[1], kdfAlgId = algIds[2];
            switch (encAlgId)
            {
                case 0x0:
                {
                    encAlgType = EncryptionAlgorithmType.AES_CBC;
                    break;
                }
                case 0x1:
                {
                    encAlgType = EncryptionAlgorithmType.AES_CTR;
                    break;
                }
                default:
                {
                    throw new ArgumentException("InitFromAlgId", "Unsupported Argument type");
                }
            }
            switch(macAlgId)
            {
                case 0x0:
                {
                    macAlgType = MacAlgorithmType.HMAC_SHA256;
                    break;
                }
                case 0x1:
                {
                    macAlgType = MacAlgorithmType.HMAC_SHA512;
                    break;
                }
                default:
                {
                    throw new ArgumentException("InitFromAlgId", "Unsupported Argument type");
                }
            }

            switch(kdfAlgId)
            {
                case 0x0:
                {
                    kdfPrf = KeyDerivationPrf.HMACSHA256;
                    break;
                }
                case 0x1:
                {
                    kdfPrf = KeyDerivationPrf.HMACSHA512;
                    break;
                }
                default:
                {
                    throw new ArgumentException("InitFromAlgId", "Unsupported Argument type");
                }
            }

            // Initialize appropriate cryptosystems
            EncryptionAlgorithm enc = new EncryptionAlgorithm(encAlgType);
            MacAlgorithm mac = new MacAlgorithm(macAlgType);
            KdfAlgorithm kdf = new KdfAlgorithm(kdfPrf);
            return new CryptoAlgorithms(enc, mac, kdf);
        }
    }

    public class EncryptionAlgorithm
    {
        public EncryptionAlgorithmType algorithmType { get; set; }
        public int blockSizeBits { get; set; }
        public int keySizeBits { get; set; }

        public int blockSizeBytes { get; set; }

        public int keySizeBytes { get; set; }

        public byte algId { get; set; }

        public EncryptionAlgorithm(EncryptionAlgorithmType type)
        {
            // Check null
            this.algorithmType = Preconditions.CheckNotNull(type);
            switch (this.algorithmType)
            {
                case EncryptionAlgorithmType.AES_CBC:
                {
                    this.blockSizeBits = 128;
                    this.keySizeBits = 256;
                    this.algId = 0x0;
                    break;
                }
                case EncryptionAlgorithmType.AES_CTR:
                {
                    this.blockSizeBits = 128;
                    this.keySizeBits = 256;
                    this.algId = 0x1;
                    break;
                }
            }
            this.blockSizeBytes = this.blockSizeBits >> 3;
            this.keySizeBytes = this.keySizeBits >> 3;
        }
    }

    public class MacAlgorithm
    {
        public int keySizeBits { get; set; }
        public int keySizeBytes { get; set; }
        public MacAlgorithmType macType { get; set; }

        public byte algId { get; set; }

        public HMAC mac { get; set; }

        public MacAlgorithm(MacAlgorithmType algorithmType)
        {
            this.macType = Preconditions.CheckNotNull(algorithmType);

            switch(this.macType)
            {
                case MacAlgorithmType.HMAC_SHA256:
                {
                    this.keySizeBits = 256;
                    this.mac = new HMACSHA256();
                    this.algId = 0x0;
                    break;
                }
                case MacAlgorithmType.HMAC_SHA512:
                {
                    this.keySizeBits = 512;
                    this.mac = new HMACSHA512();
                    this.algId = 0x1;
                    break;
                }
            }
            this.keySizeBytes = this.keySizeBits >> 3;
        }

        public HMAC GetMacAlgorithm()
        {
            return this.mac;
        }
    }

    public class KdfAlgorithm
    {
        public KeyDerivationPrf prf { get; set; }

        public int saltSizeBytes { get; set; }

        public int subKeySizeBytes { get; set; }

        public int iterCount { get; set; }

        public byte algId { get; set; }

        public KdfAlgorithm(KeyDerivationPrf prf, int saltSize = 32, int subkeySize = 32, int iterCount = 10000)
        {
            this.prf = Preconditions.CheckNotNull(prf);
            switch (this.prf)
            {
                case KeyDerivationPrf.HMACSHA1:
                {
                    throw new CryptographicException("Unsupported algorithm HmacSha1 for PRF");
                }
                case KeyDerivationPrf.HMACSHA256:
                {
                    this.algId = 0x0;
                    break;
                }
                case KeyDerivationPrf.HMACSHA512:
                {
                    this.algId = 0x1;
                    break;
                }
            }
            this.saltSizeBytes = saltSize;
            this.subKeySizeBytes = subkeySize;
            this.iterCount = iterCount;
        }
    }

   public enum EncryptionAlgorithmType 
   {
       AES_CBC,
       AES_CTR
   };

   public enum MacAlgorithmType
   {
       HMAC_SHA256,
       HMAC_SHA512
   };
}