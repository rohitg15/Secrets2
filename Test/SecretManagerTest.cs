using Xunit;
using Crypto;
using System;
using System.Linq;
using Utils;
using Models;
using System.Security;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;

namespace Test
{
    public class SecretManagerTest
    {
        public SecretsManager secretsManager { get; set; }

        public IEncryptionHelper encHelper { get; set; }

        public IMacHelper macHelper { get; set; }

        public EncryptionAlgorithm aesCbc { get; set; }

        public MacAlgorithm hs256 { get; set; }

        public MacAlgorithm hs512 { get; set; }

        public KdfAlgorithm kdfHs256 { get; set; }

        public KdfAlgorithm kdfHs512 { get; set; }

        public CryptoAlgorithms alg1 { get; set; }

        public CryptoAlgorithms alg2 { get; set; }

        private SecureString password;
        private SecureString wrongPassword;

        public SecretManagerTest()
        {
            this.encHelper = new AesHelper();
            this.macHelper = new MacHelper();
            this.secretsManager = new SecretsManager(encHelper, macHelper);

            this.aesCbc = new EncryptionAlgorithm(EncryptionAlgorithmType.AES_CBC);
            this.hs256 = new MacAlgorithm(MacAlgorithmType.HMAC_SHA256);
            this.hs512 = new MacAlgorithm(MacAlgorithmType.HMAC_SHA512);
            this.kdfHs256 = new KdfAlgorithm(KeyDerivationPrf.HMACSHA256);
            this.kdfHs512 = new KdfAlgorithm(KeyDerivationPrf.HMACSHA512);

            this.alg2 = new CryptoAlgorithms(this.aesCbc, this.hs256, this.kdfHs256);
            
            password = new SecureString();
            password.AppendChar('p');
            password.AppendChar('a');
            password.AppendChar('s');
            password.AppendChar('s');
            password.AppendChar('w');
            password.AppendChar('0');
            password.AppendChar('r');
            password.AppendChar('d');

            wrongPassword = new SecureString();
            wrongPassword.AppendChar('w');
            wrongPassword.AppendChar('r');
            wrongPassword.AppendChar('o');
            wrongPassword.AppendChar('n');
            wrongPassword.AppendChar('g');
        }

        [Fact]
        public void SecretsManagerNullEncHelper()
        {
            Assert.Throws<ArgumentNullException>(
                () =>
                    new SecretsManager(null, this.macHelper)
            );
        }

        [Fact]
        public void SecretsManagerNullMacHelper()
        {
            Assert.Throws<ArgumentNullException>(
                () =>
                    new SecretsManager(this.encHelper, null)
            );
        }

        [Fact]
        public void TestGetSessionKeysAesCbcHs256KdfHs256ValidKeys()
        {
            // given
            this.alg1 = new CryptoAlgorithms(this.aesCbc, this.hs256, this.kdfHs256);

            // when
            KeySet keys = this.secretsManager.GetSessionKeys(password, this.alg1);

            // then
            Assert.Equal(this.alg1.encAlg.keySizeBytes,  keys.encryptionKey.Length);
            Assert.Equal(this.alg1.macAlg.keySizeBytes, keys.validationKey.Length);
            Assert.NotEqual(keys.encryptionKey, keys.validationKey);
            Assert.NotEqual(keys.encryptionKey, keys.salt);

        }

        [Fact]
        public void TestGetSessionKeysAesCbcHs512KdfHs256ValidKeys()
        {
            // given
            this.alg1 = new CryptoAlgorithms(this.aesCbc, this.hs512, this.kdfHs256);

            // when
            KeySet keys = this.secretsManager.GetSessionKeys(password, this.alg1);

            // then
            Assert.Equal(this.alg1.encAlg.keySizeBytes,  keys.encryptionKey.Length);
            Assert.Equal(this.alg1.macAlg.keySizeBytes, keys.validationKey.Length);
            Assert.NotEqual(keys.encryptionKey, keys.validationKey);
            Assert.NotEqual(keys.encryptionKey, keys.salt);

        }

        [Fact]
        public void TestGetSessionKeysAesCbcHs256KdfHs512ValidKeys()
        {
            // given
            this.alg1 = new CryptoAlgorithms(this.aesCbc, this.hs256, this.kdfHs512);

            // when
            KeySet keys = this.secretsManager.GetSessionKeys(password, this.alg1);

            // then
            Assert.Equal(this.alg1.encAlg.keySizeBytes,  keys.encryptionKey.Length);
            Assert.Equal(this.alg1.macAlg.keySizeBytes, keys.validationKey.Length);
            Assert.NotEqual(keys.encryptionKey, keys.validationKey);
            Assert.NotEqual(keys.encryptionKey, keys.salt);

        }

        [Fact]
        public void TestGetSessionKeysAesCbcHs512KdfHs512ValidKeys()
        {
            // given
            this.alg1 = new CryptoAlgorithms(this.aesCbc, this.hs512, this.kdfHs512);

            // when
            KeySet keys = this.secretsManager.GetSessionKeys(password, this.alg1);

            // then
            Assert.Equal(this.alg1.encAlg.keySizeBytes,  keys.encryptionKey.Length);
            Assert.Equal(this.alg1.macAlg.keySizeBytes, keys.validationKey.Length);
            Assert.NotEqual(keys.encryptionKey, keys.validationKey);
            Assert.NotEqual(keys.encryptionKey, keys.salt);
        }

        [Fact]
        public void TestGetSessionKeysAesCbcHs256KdfHs256ValidDerivation()
        {
            // given
            this.alg1 = new CryptoAlgorithms(this.aesCbc, this.hs256, this.kdfHs256);

            // when
            KeySet keys = this.secretsManager.GetSessionKeys(password, this.alg1);
            KeySet derivedKeys = this.secretsManager.DeriveSessionKeys(password, this.alg1, keys.salt);

            // then
            Assert.Equal(keys.encryptionKey, derivedKeys.encryptionKey);
            Assert.Equal(keys.validationKey, derivedKeys.validationKey);
            Assert.Equal(keys.salt, keys.salt);
        }

        [Fact]
        public void TestGetSessionKeysAesCbcHs256KdfHs512ValidDerivation()
        {
            // given
            this.alg1 = new CryptoAlgorithms(this.aesCbc, this.hs256, this.kdfHs512);

            // when
            KeySet keys = this.secretsManager.GetSessionKeys(password, this.alg1);
            KeySet derivedKeys = this.secretsManager.DeriveSessionKeys(password, this.alg1, keys.salt);

            // then
            Assert.Equal(keys.encryptionKey, derivedKeys.encryptionKey);
            Assert.Equal(keys.validationKey, derivedKeys.validationKey);
            Assert.Equal(keys.salt, keys.salt);
        }

        [Fact]
        public void TestGetSessionKeysAesCbcHs512KdfHs256ValidDerivation()
        {
            // given
            this.alg1 = new CryptoAlgorithms(this.aesCbc, this.hs512, this.kdfHs256);

            // when
            KeySet keys = this.secretsManager.GetSessionKeys(password, this.alg1);
            KeySet derivedKeys = this.secretsManager.DeriveSessionKeys(password, this.alg1, keys.salt);

            // then
            Assert.Equal(keys.encryptionKey, derivedKeys.encryptionKey);
            Assert.Equal(keys.validationKey, derivedKeys.validationKey);
            Assert.Equal(keys.salt, keys.salt);
        }

        [Fact]
        public void TestGetSessionKeysAesCbcHs512KdfHs512ValidDerivation()
        {
            // given
            this.alg1 = new CryptoAlgorithms(this.aesCbc, this.hs512, this.kdfHs512);

            // when
            KeySet keys = this.secretsManager.GetSessionKeys(password, this.alg1);
            KeySet derivedKeys = this.secretsManager.DeriveSessionKeys(password, this.alg1, keys.salt);

            // then
            Assert.Equal(keys.encryptionKey, derivedKeys.encryptionKey);
            Assert.Equal(keys.validationKey, derivedKeys.validationKey);
            Assert.Equal(keys.salt, keys.salt);
        }

        [Fact]
        public void TestDeriveSessionKeysAesCbcHs512KdfHs512IncorrectSaltSize()
        {
            // given
            this.alg1 = new CryptoAlgorithms(this.aesCbc, this.hs512, this.kdfHs512);

            // when
            KeySet keys = this.secretsManager.GetSessionKeys(password, this.alg1);
            byte[] salt = new byte[keys.salt.Length - 1];
            Buffer.BlockCopy(keys.salt, 0, salt, 0, salt.Length);

            // then
            Assert.Throws<ArgumentException>(
                () =>
                    this.secretsManager.DeriveSessionKeys(password, this.alg1, salt)
            );
        }

        [Fact]
        public void TestGetCaonicalizedPayloadNullAlg()
        {
            byte[] salt = new byte[1];
            byte[] ivOrNonce = new byte[1];
            byte[] secretId = new byte[1];
            byte[] encSecret = new byte[1];
            Assert.Throws<ArgumentNullException>(
                () =>
                    this.secretsManager.GetCanonicalizedPayload(null, salt, ivOrNonce, secretId, encSecret)
            );
        }

        [Fact]
        public void TestGetCaonicalizedPayloadNullSalt()
        {
            byte[] algs = new byte[1];
            byte[] ivOrNonce = new byte[1];
            byte[] secretId = new byte[1];
            byte[] encSecret = new byte[1];
            Assert.Throws<ArgumentNullException>(
                () =>
                    this.secretsManager.GetCanonicalizedPayload(algs, null, ivOrNonce, secretId, encSecret)
            );
        }


        [Fact]
        public void TestGetCaonicalizedPayloadNullIvOrNonce()
        {
            byte[] algs = new byte[1];
            byte[] salt = new byte[1];
            byte[] secretId = new byte[1];
            byte[] encSecret = new byte[1];
            Assert.Throws<ArgumentNullException>(
                () =>
                    this.secretsManager.GetCanonicalizedPayload(algs, salt, null, secretId, encSecret)
            );
        }

        [Fact]
        public void TestGetCaonicalizedPayloadNullSecretId()
        {   
            byte[] algs = new byte[1];
            byte[] salt = new byte[1];
            byte[] ivOrNonce = new byte[1];
            byte[] encSecret = new byte[1];
            Assert.Throws<ArgumentNullException>(
                () =>
                    this.secretsManager.GetCanonicalizedPayload(algs, salt, ivOrNonce, null, encSecret)
            );
        }

        [Fact]
        public void TestGetCaonicalizedPayloadNullEncSecret()
        {
            byte[] algs = new byte[1];
            byte[] salt = new byte[1];
            byte[] ivOrNonce = new byte[1];
            byte[] secretId = new byte[1];
            Assert.Throws<ArgumentNullException>(
                () =>
                    this.secretsManager.GetCanonicalizedPayload(algs, salt, ivOrNonce, secretId, null)
            );
        }


        [Fact]
        public void TestGetCaonicalizedPayloadValid()
        {
            // given
            byte[] algs = Enumerable.Repeat((byte)0x10, 3).ToArray();
            byte[] salt = Enumerable.Repeat((byte)0x20, 32).ToArray();;
            byte[] ivOrNonce = Enumerable.Repeat((byte)0x30, 16).ToArray();;
            byte[] secretId = Enumerable.Repeat((byte)0x40, 21).ToArray();
            byte[] encSecret = Enumerable.Repeat((byte)0x50, 1024).ToArray();
            
            // when
            byte[] payload = this.secretsManager.GetCanonicalizedPayload(algs, salt, ivOrNonce, secretId, encSecret);
            
            // then
            Assert.Equal(payload.Length, algs.Length + salt.Length + ivOrNonce.Length + secretId.Length + encSecret.Length);

            int start = 0;
            // check algs
            for(int i = 0; i < algs.Length; ++i)
            {
                Assert.True(algs[i] == payload[start + i]);
            }
            start += algs.Length;

            // check salt
            for(int i = 0; i < salt.Length; ++i)
            {
                Assert.True(salt[i] == payload[start + i]);
            }
            start += salt.Length;

            // check ivOrNonce
            for(int i = 0; i < ivOrNonce.Length; ++i)
            {
                Assert.True(ivOrNonce[i] == payload[start + i]);
            }
            start += ivOrNonce.Length;

            // check secretId
            for(int i = 0; i < secretId.Length; ++i)
            {
                Assert.True(secretId[i] == payload[start + i]);
            }
            start += secretId.Length;

            // check encrypted Secret
            for(int i = 0; i < encSecret.Length; ++i)
            {
                Assert.True(encSecret[i] == payload[start + i]);
            }
        }

        [Fact]
        public void TestProtectNullPassword()
        {
            byte[] secret = Enumerable.Repeat((byte)0x10, 16).ToArray();
            SecureString nullPassword = null;
            Assert.Throws<ArgumentNullException>(
                () =>
                    this.secretsManager.Protect(nullPassword, this.alg2, "secretid", secret)
            );
        }

        [Fact]
        public void TestProtectNullAlgorithm()
        {
            byte[] secret = Enumerable.Repeat((byte)0x10, 16).ToArray();
            Assert.Throws<ArgumentNullException>(
                () =>
                    this.secretsManager.Protect(password, null, "secretid", secret)
            );
        }


        [Fact]
        public void TestProtectNullSecretId()
        {
            byte[] secret = Enumerable.Repeat((byte)0x10, 16).ToArray();
            Assert.Throws<ArgumentNullException>(
                () =>
                    this.secretsManager.Protect(password, this.alg2, null, secret)
            );
        }


        [Fact]
        public void TestProtectNullSecretBytes()
        {
            Assert.Throws<ArgumentNullException>(
                () =>
                    this.secretsManager.Protect(password, this.alg2, "secretid", null)
            );
        }

        [Fact]
        public void TestProtectInvalidSecretIdLength()
        {
            byte[] secret = Enumerable.Repeat((byte)0x10, 16).ToArray();
            byte[] secretIdBytes = Enumerable.Repeat((byte)0x10, this.secretsManager.maxSecretIdBytes + 1).ToArray();
            string secretId = StringUtils.GetString(secretIdBytes);
            Assert.Throws<ArgumentOutOfRangeException>(
                () =>
                    this.secretsManager.Protect(password, this.alg2, secretId, secret)
            );
        }

        [Fact]
        public void TestProtectInvalidSecretLength()
        {
            byte[] secret = Enumerable.Repeat((byte)0x10, this.secretsManager.maxSecretBytes + 1).ToArray();
            string secretId = "secretId";

            Assert.Throws<ArgumentOutOfRangeException>(
                () =>
                    this.secretsManager.Protect(password, this.alg2, secretId, secret)
            );
        }

        [Fact]
        public void TestProtectSameSecretCbcHs512kdf512()
        {
            // given
            CryptoAlgorithms alg = new CryptoAlgorithms(this.aesCbc, this.hs512, this.kdfHs512);
            string secretId = "secretId";
            byte[] secretBytes = Enumerable.Repeat((byte)0x10, 16).ToArray();
            string tag = "tag";

            // when
            Secret secret1 = this.secretsManager.Protect(password, alg, secretId, secretBytes, tag);
            Secret secret2 = this.secretsManager.Protect(password, alg, secretId, secretBytes, tag);

            // then
            Assert.NotEqual(secret1.b64IvOrNonce, secret2.b64IvOrNonce);
            Assert.NotEqual(secret1.b64Salt, secret2.b64Salt);
            Assert.NotEqual(secret1.b64EncryptedSecret, secret2.b64EncryptedSecret);
            Assert.NotEqual(secret1.b64Mac, secret2.b64Mac);
        }

        [Fact]
        public void TestProtectSameSecretCbcHs256kdf256()
        {
            // given
            CryptoAlgorithms alg = new CryptoAlgorithms(this.aesCbc, this.hs256, this.kdfHs256);
            string secretId = "secretId";
            byte[] secretBytes = Enumerable.Repeat((byte)0x10, 16).ToArray();
            string tag = "tag";

            // when
            Secret secret1 = this.secretsManager.Protect(password, alg, secretId, secretBytes, tag);
            Secret secret2 = this.secretsManager.Protect(password, alg, secretId, secretBytes, tag);

            // then
            Assert.NotEqual(secret1.b64IvOrNonce, secret2.b64IvOrNonce);
            Assert.NotEqual(secret1.b64Salt, secret2.b64Salt);
            Assert.NotEqual(secret1.b64EncryptedSecret, secret2.b64EncryptedSecret);
            Assert.NotEqual(secret1.b64Mac, secret2.b64Mac);
        }

        [Fact]
        public void TestUnprotectNullPassword()
        {
            SecureString nullPassword = null;
            Secret secret = new Secret("", "", "", "", "", DateTime.UtcNow, "", "");

            Assert.Throws<ArgumentNullException>(
                () =>
                    this.secretsManager.Unprotect(nullPassword, secret)
            );
        }


        [Fact]
        public void TestUnprotectNullSecret()
        {
            Assert.Throws<ArgumentNullException>(
                () =>
                    this.secretsManager.Unprotect(password, null)
            );
        }

        [Fact]
        public void TestUnprotectInvalidB64AlgIds()
        {
            byte[] algIds = Enumerable.Repeat((byte)0x1, 3).ToArray();
            byte[] salt = Enumerable.Repeat((byte)0x10, 16).ToArray();
            byte[] iv = Enumerable.Repeat((byte)0x10, this.alg2.encAlg.keySizeBytes).ToArray();
            byte[] ciphertext = Enumerable.Repeat((byte)0x10, 32).ToArray();
            byte[] expMac = Enumerable.Repeat((byte)0x10, this.alg2.macAlg.keySizeBytes).ToArray();

            string b64AlgIds = ";;'.";
            string b64Salt = StringUtils.GetBase64String(salt);
            string b64Iv = StringUtils.GetBase64String(iv);
            string secretId = "secretId";
            string b64Ciphertext = StringUtils.GetBase64String(ciphertext);
            string b64Mac = StringUtils.GetBase64String(expMac);

            Secret secret = new Secret(b64AlgIds, secretId, b64Ciphertext, b64Salt, b64Iv, DateTime.UtcNow, "", b64Mac);
            
            Assert.Throws<FormatException>(
                () =>
                    this.secretsManager.Unprotect(password, secret)
            );
        }

        [Fact]
        public void TestUnprotectInvalidB64Salt()
        {
            byte[] algIds = Enumerable.Repeat((byte)0x1, 3).ToArray();
            byte[] salt = Enumerable.Repeat((byte)0x10, 16).ToArray();
            byte[] iv = Enumerable.Repeat((byte)0x10, this.alg2.encAlg.keySizeBytes).ToArray();
            byte[] ciphertext = Enumerable.Repeat((byte)0x10, 32).ToArray();
            byte[] expMac = Enumerable.Repeat((byte)0x10, this.alg2.macAlg.keySizeBytes).ToArray();

            string b64AlgIds = StringUtils.GetBase64String(algIds);
            string b64Salt = ";'.,";
            string b64Iv = StringUtils.GetBase64String(iv);
            string secretId = "secretId";
            string b64Ciphertext = StringUtils.GetBase64String(ciphertext);
            string b64Mac = StringUtils.GetBase64String(expMac);

            Secret secret = new Secret(b64AlgIds, secretId, b64Ciphertext, b64Salt, b64Iv, DateTime.UtcNow, "", b64Mac);
            
            Assert.Throws<FormatException>(
                () =>
                    this.secretsManager.Unprotect(password, secret)
            );
        }


        [Fact]
        public void TestUnprotectInvalidB64Iv()
        {
            byte[] algIds = Enumerable.Repeat((byte)0x1, 3).ToArray();
            byte[] salt = Enumerable.Repeat((byte)0x10, 16).ToArray();
            byte[] iv = Enumerable.Repeat((byte)0x10, this.alg2.encAlg.keySizeBytes).ToArray();
            byte[] ciphertext = Enumerable.Repeat((byte)0x10, 32).ToArray();
            byte[] expMac = Enumerable.Repeat((byte)0x10, this.alg2.macAlg.keySizeBytes).ToArray();

            string b64AlgIds = StringUtils.GetBase64String(algIds);
            string b64Salt = StringUtils.GetBase64String(salt);
            string b64Iv = ";.,";
            string secretId = "secretId";
            string b64Ciphertext = StringUtils.GetBase64String(ciphertext);
            string b64Mac = StringUtils.GetBase64String(expMac);

            Secret secret = new Secret(b64AlgIds, secretId, b64Ciphertext, b64Salt, b64Iv, DateTime.UtcNow, "", b64Mac);
            
            Assert.Throws<FormatException>(
                () =>
                    this.secretsManager.Unprotect(password, secret)
            );
        }


        [Fact]
        public void TestUnprotectInvalidB64Ciphertext()
        {
            byte[] algIds = Enumerable.Repeat((byte)0x1, 3).ToArray();
            byte[] salt = Enumerable.Repeat((byte)0x10, 16).ToArray();
            byte[] iv = Enumerable.Repeat((byte)0x10, this.alg2.encAlg.keySizeBytes).ToArray();
            byte[] ciphertext = Enumerable.Repeat((byte)0x10, 32).ToArray();
            byte[] expMac = Enumerable.Repeat((byte)0x10, this.alg2.macAlg.keySizeBytes).ToArray();

            string b64AlgIds = StringUtils.GetBase64String(algIds);
            string b64Salt = StringUtils.GetBase64String(salt);
            string b64Iv = StringUtils.GetBase64String(iv);
            string secretId = "secretId";
            string b64Ciphertext = ";,";
            string b64Mac = StringUtils.GetBase64String(expMac);

            Secret secret = new Secret(b64AlgIds, secretId, b64Ciphertext, b64Salt, b64Iv, DateTime.UtcNow, "", b64Mac);
            
            Assert.Throws<FormatException>(
                () =>
                    this.secretsManager.Unprotect(password, secret)
            );
        }


        [Fact]
        public void TestUnprotectInvalidB64Mac()
        {
            byte[] algIds = Enumerable.Repeat((byte)0x1, 3).ToArray();
            byte[] salt = Enumerable.Repeat((byte)0x10, 16).ToArray();
            byte[] iv = Enumerable.Repeat((byte)0x10, this.alg2.encAlg.keySizeBytes).ToArray();
            byte[] ciphertext = Enumerable.Repeat((byte)0x10, 32).ToArray();
            byte[] expMac = Enumerable.Repeat((byte)0x10, this.alg2.macAlg.keySizeBytes).ToArray();

            string b64AlgIds = StringUtils.GetBase64String(algIds);
            string b64Salt = StringUtils.GetBase64String(salt);
            string b64Iv = StringUtils.GetBase64String(iv);
            string secretId = "secretId";
            string b64Ciphertext = StringUtils.GetBase64String(ciphertext);
            string b64Mac = ";.,";

            Secret secret = new Secret(b64AlgIds, secretId, b64Ciphertext, b64Salt, b64Iv, DateTime.UtcNow, "", b64Mac);
            
            Assert.Throws<FormatException>(
                () =>
                    this.secretsManager.Unprotect(password, secret)
            );
        }


        [Fact]
        public void TestUnProtectSecret()
        {
            // given
            CryptoAlgorithms alg = new CryptoAlgorithms(this.aesCbc, this.hs512, this.kdfHs512);
            string secretId = "secretId";
            byte[] secretBytes = Enumerable.Repeat((byte)0x10, 16).ToArray();
            string tag = "tag";

            // when
            Secret secret = this.secretsManager.Protect(password, alg, secretId, secretBytes, tag);
            byte[] retrievedSecret = this.secretsManager.Unprotect(password, secret);
            
            // then
            Assert.Equal(retrievedSecret, secretBytes);
        }

        [Fact]
        public void TestUnProtectSecretWrongPassword()
        {
            // given
            CryptoAlgorithms alg = new CryptoAlgorithms(this.aesCbc, this.hs512, this.kdfHs512);
            string secretId = "secretId";
            byte[] secretBytes = Enumerable.Repeat((byte)0x10, 16).ToArray();
            string tag = "tag";

            Console.WriteLine("{0} : {1}", password.ToString(), wrongPassword.ToString());
            // when
            Secret secret = this.secretsManager.Protect(password, alg, secretId, secretBytes, tag);

            // then - signature validation should fail
            Assert.Throws<ApplicationException>(
                () => 
                    this.secretsManager.Unprotect(wrongPassword, secret)
            );
        }

        [Fact]
        public void TestUnProtectSecretTamperedSalt()
        {
            // given
            CryptoAlgorithms alg = new CryptoAlgorithms(this.aesCbc, this.hs512, this.kdfHs512);
            string secretId = "secretId";
            byte[] secretBytes = Enumerable.Repeat((byte)0x10, 16).ToArray();
            string tag = "tag";
            
            // when
            Secret secret = this.secretsManager.Protect(password, alg, secretId, secretBytes, tag);
            byte[] saltBytes = StringUtils.GetBytesFromBase64(secret.b64Salt);
            saltBytes[saltBytes.Length - 1] = (byte)(saltBytes[saltBytes.Length - 1] + 0x1);
            secret.b64Salt = StringUtils.GetBase64String(saltBytes);

            // then - Signature validation should fail
            Assert.Throws<ApplicationException>(
                () => 
                    this.secretsManager.Unprotect(wrongPassword, secret)
            );
        }


        [Fact]
        public void TestUnProtectSecretTamperedPayload()
        {
            // given
            CryptoAlgorithms alg = new CryptoAlgorithms(this.aesCbc, this.hs512, this.kdfHs512);
            string secretId = "secretId";
            byte[] secretBytes = Enumerable.Repeat((byte)0x10, 16).ToArray();
            string tag = "tag";
            
            // when
            Secret secret = this.secretsManager.Protect(password, alg, secretId, secretBytes, tag);
            byte[] payloadBytes = StringUtils.GetBytesFromBase64(secret.b64EncryptedSecret);
            payloadBytes[payloadBytes.Length - 1] = (byte)(payloadBytes[payloadBytes.Length - 1] + 0x1);
            secret.b64EncryptedSecret = StringUtils.GetBase64String(payloadBytes);

            // then - Signature validation should fail
            Assert.Throws<ApplicationException>(
                () => 
                    this.secretsManager.Unprotect(wrongPassword, secret)
            );
        }

        [Fact]
        public void TestUnProtectSecretTamperedIv()
        {
            // given
            CryptoAlgorithms alg = new CryptoAlgorithms(this.aesCbc, this.hs512, this.kdfHs512);
            string secretId = "secretId";
            byte[] secretBytes = Enumerable.Repeat((byte)0x10, 16).ToArray();
            string tag = "tag";
            
            // when
            Secret secret = this.secretsManager.Protect(password, alg, secretId, secretBytes, tag);
            byte[] ivBytes = StringUtils.GetBytesFromBase64(secret.b64IvOrNonce);
            ivBytes[ivBytes.Length - 1] = (byte)(ivBytes[ivBytes.Length - 1] + 0x1);
            secret.b64IvOrNonce = StringUtils.GetBase64String(ivBytes);

            // then - Signature validation should fail
            Assert.Throws<ApplicationException>(
                () => 
                    this.secretsManager.Unprotect(wrongPassword, secret)
            );
        }

        [Fact]
        public void TestUnProtectSecretTamperedId()
        {
            // given
            CryptoAlgorithms alg = new CryptoAlgorithms(this.aesCbc, this.hs512, this.kdfHs512);
            string secretId = "secretId";
            byte[] secretBytes = Enumerable.Repeat((byte)0x10, 16).ToArray();
            string tag = "tag";
            
            // when
            Secret secret = this.secretsManager.Protect(password, alg, secretId, secretBytes, tag);
            byte[] idBytes = StringUtils.GetBytes(secret.secretId);
            idBytes[idBytes.Length - 1] = (byte)(idBytes[idBytes.Length - 1] + 0x1);
            secret.b64IvOrNonce = StringUtils.GetBase64String(idBytes);

            // then - Signature validation should fail
            Assert.Throws<ApplicationException>(
                () => 
                    this.secretsManager.Unprotect(wrongPassword, secret)
            );
        }


    }
}