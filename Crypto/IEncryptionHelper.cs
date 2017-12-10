using System;
using System.Threading.Tasks;

namespace Crypto
{
    public interface IEncryptionHelper
    {
        void Init(EncryptionAlgorithm algorithm, byte[] key, byte[] iv);
        byte[] EncryptBytes(byte[] plaintext);
        byte[] DecryptBytes(byte[] ciphertext);
    }
}