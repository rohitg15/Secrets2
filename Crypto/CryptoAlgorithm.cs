using System.Security.Cryptography;

namespace Crypto
{

    public class EncryptionAlgorithm
    {
        public EncryptionAlgorithmType algorithmType { get; set; }
        public int blockSizeBits { get; set; }
        public int keySizeBits { get; set; }

        public EncryptionAlgorithm(EncryptionAlgorithmType type)
        {
            // Check null
            this.algorithmType = type;    
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
            this.macType = algorithmType;

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