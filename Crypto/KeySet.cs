
using Utils;

namespace Crypto
{
    public class KeySet
    {
        public byte[] encryptionKey { get; set; }
        public byte[] validationKey { get; set; }

        public byte[] salt { get; set; }

        public KeySet(byte[] encryptionKey, byte[] validationKey, byte[] salt)
        {
            this.encryptionKey = Preconditions.CheckNotNull(encryptionKey);
            this.validationKey = Preconditions.CheckNotNull(validationKey);
            this.salt = Preconditions.CheckNotNull(salt);
        }
    }
}