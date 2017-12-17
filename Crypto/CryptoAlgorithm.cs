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
    }

    public class EncryptionAlgorithm
    {
        public EncryptionAlgorithmType algorithmType { get; set; }
        public int blockSizeBits { get; set; }
        public int keySizeBits { get; set; }

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
                    break;
                }
                case EncryptionAlgorithmType.AES_CTR:
                {
                    this.blockSizeBits = 128;
                    this.keySizeBits = 256;
                    break;
                }
            }

        }
    }

    public class MacAlgorithm
    {
        public int keySizeBits { get; set; }
        public MacAlgorithmType macType { get; set; }

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
                    break;
                }
                case MacAlgorithmType.HMAC_SHA512:
                {
                    this.keySizeBits = 512;
                    this.mac = new HMACSHA512();
                    break;
                }
            }
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

        public KdfAlgorithm(KeyDerivationPrf prf, int saltSize = 32, int subkeySize = 32, int iterCount = 10000)
        {
            this.prf = Preconditions.CheckNotNull(prf);
            switch (this.prf)
            {
                case KeyDerivationPrf.HMACSHA1:
                {
                    throw new CryptographicException("Unsupported algorithm HmacSha1 for PRF");
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