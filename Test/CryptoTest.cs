using System;
using Xunit;
using System.Security.Cryptography;
using Crypto;
using Utils;

namespace Test
{
    public class CryptoTest
    {
        public byte[] key { get; set; }
        public byte[] iv { get; set; }
        public EncryptionAlgorithm aesCbc { get; set; }

        public CryptoTest()
        {
            this.aesCbc = new EncryptionAlgorithm(EncryptionAlgorithmType.AES_CBC);
            this.key = new byte[aesCbc.keySizeBits / 8];
            this.iv = new byte[aesCbc.blockSizeBits / 8];
            
            var csprng = RandomNumberGenerator.Create();
            csprng.GetBytes(key, 0, key.Length);
            csprng.GetBytes(iv, 0, iv.Length);
        }

        [Fact]
        public void TestEncryptShortString()
        {
            
            
            IEncryptionHelper cryptoService = new AesHelper();
            cryptoService.Init(this.aesCbc, this.key, this.iv);
            string plaintext = "Hello World!";
            byte[] plaintextBytes = StringUtils.GetBytes(plaintext);
            byte[] cipherBytes = cryptoService.EncryptBytesAsync(plaintextBytes).GetAwaiter().GetResult();

            byte[] decryptedBytes = cryptoService.DecryptBytesAsync(cipherBytes).GetAwaiter().GetResult();
            string decryptedPlaintext = StringUtils.GetString(decryptedBytes);

            Assert.Equal(decryptedPlaintext, plaintext);

        }
    }
}
