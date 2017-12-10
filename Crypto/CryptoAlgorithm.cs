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
   public enum EncryptionAlgorithmType 
   {
       AES_CBC,
       AES_CTR,
       UNSUPPORTED
   };
}