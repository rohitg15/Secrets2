using System;
using System.Threading.Tasks;

namespace Crypto
{
    public interface IEncryptionHelper
    {
        void Init(EncryptionAlgorithm algorithm, byte[] key, byte[] iv);
        Task<byte[]> EncryptBytesAsync(byte[] plaintext);
        Task<byte[]> DecryptBytesAsync(byte[] ciphertext);
    }
}