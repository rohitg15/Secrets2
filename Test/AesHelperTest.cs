using System;
using Xunit;
using System.Security.Cryptography;
using Crypto;
using Utils;

namespace Test
{
    public class AesHelperTest
    {
        public byte[] key { get; set; }
        public byte[] iv { get; set; }
        public EncryptionAlgorithm aesCbc { get; set; }

        public AesHelperTest()
        {
            this.aesCbc = new EncryptionAlgorithm(EncryptionAlgorithmType.AES_CBC);
            this.key = new byte[aesCbc.keySizeBits / 8];
            this.iv = new byte[aesCbc.blockSizeBits / 8];
            
            var csprng = RandomNumberGenerator.Create();
            csprng.GetBytes(key, 0, key.Length);
            csprng.GetBytes(iv, 0, iv.Length);
        }

        [Fact]
        public void TestInitNullAlgorithm()
        {
            IEncryptionHelper cryptoService = new AesHelper();
            Assert.Throws<ArgumentNullException>(
                    () => 
                        cryptoService.Init(null, this.key, this.iv)
                );
        }

        [Fact]
        public void TestInitNullKey()
        {
            IEncryptionHelper cryptoService = new AesHelper();
            Assert.Throws<ArgumentNullException>(
                    () => 
                        cryptoService.Init(this.aesCbc, null, this.iv)
                );
        }

        [Fact]
        public void TestInitNullIv()
        {
            IEncryptionHelper cryptoService = new AesHelper();
            Assert.Throws<ArgumentNullException>(
                    () => 
                        cryptoService.Init(this.aesCbc, this.key, null)
                );
        }

        [Fact]
        public void TestInitUnknownAlgorithm()
        {
            IEncryptionHelper cryptoService = new AesHelper();
            EncryptionAlgorithm unsupportedAlgorithm = 
                    new EncryptionAlgorithm(EncryptionAlgorithmType.UNSUPPORTED);
            Assert.Throws<CryptographicException>(
                    () => 
                        cryptoService.Init(unsupportedAlgorithm, this.key, this.iv)
                );
        }

        [Fact]
        public void TestInitInvalidKeyLength()
        {
            IEncryptionHelper cryptoService = new AesHelper();
            byte[] invalidKey = new byte[16];
            Assert.Throws<CryptographicException>(
                    () => 
                        cryptoService.Init(this.aesCbc, invalidKey, this.iv)
                );
        }


        [Fact]
        public void TestInitInvalidIvLength()
        {
            IEncryptionHelper cryptoService = new AesHelper();
            var invalidIv = new byte[8];
            Assert.Throws<CryptographicException>(
                    () => 
                        cryptoService.Init(this.aesCbc, invalidIv, this.iv)
                );
        }

        [Fact]
        public void TestEncryptBytesNullPlaintext()
        {
            IEncryptionHelper cryptoService = new AesHelper();
            cryptoService.Init(this.aesCbc, this.key, this.iv);
            
            Assert.Throws<ArgumentNullException>(
                    () =>
                        cryptoService.EncryptBytes(null)
                );
        }
        
        [Fact]
        public void TestDecryptBytesNullPlaintext()
        {
            IEncryptionHelper cryptoService = new AesHelper();
            cryptoService.Init(this.aesCbc, this.key, this.iv);
            
            Assert.Throws<ArgumentNullException>(
                    () =>
                        cryptoService.DecryptBytes(null)
                );
        }

        [Fact]
        public void TestAesCbcShortPlaintext()
        {
            // initialization
            IEncryptionHelper cryptoService = new AesHelper();
            string plaintext = "Hello World!";

            // when
            cryptoService.Init(this.aesCbc, this.key, this.iv);
            byte[] plaintextBytes = StringUtils.GetBytes(plaintext);
            byte[] cipherBytes = cryptoService.EncryptBytes(plaintextBytes);

            byte[] decryptedBytes = cryptoService.DecryptBytes(cipherBytes);
            string decryptedPlaintext = StringUtils.GetString(decryptedBytes);

            // then
            Assert.Equal(decryptedBytes.Length, plaintextBytes.Length);
            Assert.Equal(decryptedBytes, plaintextBytes);
            Assert.Equal(decryptedPlaintext, plaintext);
        }


        [Fact]
        public void TestAesCbcLongPlaintext()
        {
            // initialization
            IEncryptionHelper cryptoService = new AesHelper();
            var plaintextBytes = new byte[1024*1024];
            
            // when
            cryptoService.Init(this.aesCbc, this.key, this.iv);
            byte[] cipherBytes = cryptoService.EncryptBytes(plaintextBytes);
            byte[] decryptedBytes = cryptoService.DecryptBytes(cipherBytes);

            // then
            Assert.Equal(decryptedBytes.Length, plaintextBytes.Length);
            Assert.Equal(decryptedBytes, plaintextBytes);
        }

        [Fact]
        public void TestAesCbcRandomizedEncryptionSamePlaintext()
        {
            // initialize
            IEncryptionHelper cryptoService1 = new AesHelper();
            IEncryptionHelper cryptoService2 = new AesHelper();
            var iv1 = new byte[16];
            var iv2 = new byte[16];
            var csprng = RandomNumberGenerator.Create();
            csprng.GetBytes(iv1, 0, iv1.Length);
            csprng.GetBytes(iv2, 0, iv2.Length);
            var plaintextBytes = new byte[1024];

            // Same key, but different iv
            cryptoService1.Init(this.aesCbc, this.key, iv1);
            cryptoService2.Init(this.aesCbc, this.key, iv2);

            // when
            var cipherBytes1 = cryptoService1.EncryptBytes(plaintextBytes);
            var cipherBytes2 = cryptoService2.EncryptBytes(plaintextBytes);

            //then
            Assert.NotEqual(cipherBytes1, cipherBytes2);
        }

    }
}
