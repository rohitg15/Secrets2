using Xunit;
using Dal;
using System;
using System.Linq;
using Models;
using Crypto;
using System.Security;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;


namespace Test
{
    public class FileStorageTest
    {
        public IStorage dataStore { get; set; }
        public string rootDir { get; set; }

        public FileStorageTest()
        {
            this.rootDir = ".";
            this.dataStore = new FileStorage(this.rootDir);
        }

        [Fact]
        public void FileStorageNullRootDir()
        {
            Assert.Throws<ArgumentNullException>(
                () =>
                    new FileStorage(null)
            );
        }

        [Fact]
        public void ReadSecretNullSecretId()
        {
            Assert.Throws<ArgumentNullException>(
                () =>
                    this.dataStore.ReadSecret(null)
            );
        }

        [Fact]
        public void ReadSecretInvalidFileName()
        {
            Assert.Throws<Exception>(
                () =>
                    this.dataStore.ReadSecret("SomeRandomFile")
            );
        }

        [Fact]
        public void WriteSecretNullSecret()
        {
            Assert.Throws<ArgumentNullException>(
                () =>
                    this.dataStore.WriteSecret(null)
            );
        }

        [Fact]
        public void WriteSecretValidSecret()
        {
            // given
            SecureString password = new SecureString();
            password.AppendChar('p');
            password.AppendChar('a');
            password.AppendChar('s');
            password.AppendChar('s');
            password.AppendChar('w');
            password.AppendChar('0');
            password.AppendChar('r');
            password.AppendChar('d');
            

            CryptoAlgorithms alg = new CryptoAlgorithms(
                new EncryptionAlgorithm(EncryptionAlgorithmType.AES_CBC),
                new MacAlgorithm(MacAlgorithmType.HMAC_SHA256),
                new KdfAlgorithm(KeyDerivationPrf.HMACSHA256)
                );
            string secretId = "secretId";
            byte[] secretBytes = Enumerable.Repeat((byte)0x10, 16).ToArray();
            string tag = "tag";
            SecretsManager secretsManager = new SecretsManager(
                new AesHelper(),
                new MacHelper()
            );

            // when
            Secret secret = secretsManager.Protect(password, alg, secretId, secretBytes, tag);

            // then
            this.dataStore.WriteSecret(secret);
        }

        [Fact]
        public void WriteSecretThenReadSecret()
        {
            // given
            SecureString password = new SecureString();
            password.AppendChar('p');
            password.AppendChar('a');
            password.AppendChar('s');
            password.AppendChar('s');
            password.AppendChar('w');
            password.AppendChar('0');
            password.AppendChar('r');
            password.AppendChar('d');
            
            CryptoAlgorithms alg = new CryptoAlgorithms(
                new EncryptionAlgorithm(EncryptionAlgorithmType.AES_CBC),
                new MacAlgorithm(MacAlgorithmType.HMAC_SHA256),
                new KdfAlgorithm(KeyDerivationPrf.HMACSHA256)
                );
            string secretId = "secretId";
            byte[] secretBytes = Enumerable.Repeat((byte)0x10, 16).ToArray();
            string tag = "tag";
            SecretsManager secretsManager = new SecretsManager(
                new AesHelper(),
                new MacHelper()
            );

            // when
            Secret expectedSecret = secretsManager.Protect(password, alg, secretId, secretBytes, tag);
            this.dataStore.WriteSecret(expectedSecret);
            Secret actualSecret = this.dataStore.ReadSecret(expectedSecret.secretId);
            

            // then
            Assert.Equal(expectedSecret.secretId, actualSecret.secretId);
            Assert.Equal(expectedSecret.b64AlgIds, actualSecret.b64AlgIds);
            Assert.Equal(expectedSecret.b64EncryptedSecret, actualSecret.b64EncryptedSecret);
            Assert.Equal(expectedSecret.b64Salt, actualSecret.b64Salt);
            Assert.Equal(expectedSecret.b64IvOrNonce, actualSecret.b64IvOrNonce);
            Assert.Equal(expectedSecret.b64Mac, actualSecret.b64Mac);
            Assert.Equal(expectedSecret.createdTimeStamp, actualSecret.createdTimeStamp);
            Assert.Equal(expectedSecret.tag, actualSecret.tag);

            SecretsManager decryptionManager = new SecretsManager(
                new AesHelper(),
                new MacHelper()
            );
            byte[] retrievedSecretBytes = decryptionManager.Unprotect(password, actualSecret);
            Assert.Equal(secretBytes.Length, retrievedSecretBytes.Length);
            Assert.Equal(secretBytes, retrievedSecretBytes);
        }


    }
}