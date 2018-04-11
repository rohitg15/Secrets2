using Xunit;
using Dal;
using System;
using System.Linq;
using Models;
using Utils;
using Crypto;
using System.Security;
using System.IO;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System.Security.Cryptography;


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
            Secret secret = secretsManager.Protect(ref password, alg, secretId, secretBytes, tag);

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
            Secret expectedSecret = secretsManager.Protect(ref password, alg, secretId, secretBytes, tag);
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
            byte[] retrievedSecretBytes = decryptionManager.Unprotect(ref password, actualSecret);
            Assert.Equal(secretBytes.Length, retrievedSecretBytes.Length);
            Assert.Equal(secretBytes, retrievedSecretBytes);
        }

        [Fact]
        public void DeleteSecretNullSecretId()
        {
            Assert.Throws<ArgumentNullException>(
                () =>
                    this.dataStore.DeleteSecret(null)
            );
        }

        [Fact]
        public void DeleteSecretMissingFile()
        {
            // this code is expected to not throw since .NET's File.Delete()
            // does not throw in the event of an invalid file name
            this.dataStore.DeleteSecret("THis_secret_Id_Does_Not_Exist!!!!");
        }

        [Fact]
        public void DeleteSecretFile()
        {
            // generate random secretId
            var csprng = RandomNumberGenerator.Create();
            byte[] secretIdBytes = new byte[16];
            csprng.GetBytes(secretIdBytes);
            string secretId = StringUtils.GetString(secretIdBytes);

            // generate secretPath
            byte[] digestBytes = StringUtils.GetBytes(HashProvider.GetSha256Digest(secretId));
            string fileName = "." + StringUtils.GetHexFromBytes(digestBytes) + ".json";
            string secretFilePath = Path.Combine(this.rootDir, fileName);   
            
            // create file at secretPath
            using(FileStream fs = File.Create(secretFilePath))
            {
                fs.Write(secretIdBytes, 0, secretIdBytes.Length);
            }

            // when
            this.dataStore.DeleteSecret(secretId);

            // then
            Assert.True(false == File.Exists(secretFilePath));
        }


    }
}