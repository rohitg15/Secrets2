using Xunit;
using Crypto;
using System;
using System.Linq;
using Utils;
using Models;
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
            string password = "NeverUseThisPasswo0rd12$34";
            this.alg1 = new CryptoAlgorithms(this.aesCbc, this.hs256, this.kdfHs256);

            // when
            KeySet keys = this.secretsManager.GetSessionKeys(ref password, this.alg1);

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
            string password = "NeverUseThisPasswo0rd12$34";
            this.alg1 = new CryptoAlgorithms(this.aesCbc, this.hs512, this.kdfHs256);

            // when
            KeySet keys = this.secretsManager.GetSessionKeys(ref password, this.alg1);

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
            string password = "NeverUseThisPasswo0rd12$34";
            this.alg1 = new CryptoAlgorithms(this.aesCbc, this.hs256, this.kdfHs512);

            // when
            KeySet keys = this.secretsManager.GetSessionKeys(ref password, this.alg1);

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
            string password = "NeverUseThisPasswo0rd12$34";
            this.alg1 = new CryptoAlgorithms(this.aesCbc, this.hs512, this.kdfHs512);

            // when
            KeySet keys = this.secretsManager.GetSessionKeys(ref password, this.alg1);

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
            string password = "NeverUseThisPasswo0rd12$34";
            this.alg1 = new CryptoAlgorithms(this.aesCbc, this.hs256, this.kdfHs256);

            // when
            KeySet keys = this.secretsManager.GetSessionKeys(ref password, this.alg1);
            KeySet derivedKeys = this.secretsManager.DeriveSessionKeys(ref password, this.alg1, keys.salt);

            // then
            Assert.Equal(keys.encryptionKey, derivedKeys.encryptionKey);
            Assert.Equal(keys.validationKey, derivedKeys.validationKey);
            Assert.Equal(keys.salt, keys.salt);
        }

        [Fact]
        public void TestGetSessionKeysAesCbcHs256KdfHs512ValidDerivation()
        {
            // given
            string password = "NeverUseThisPasswo0rd12$34";
            this.alg1 = new CryptoAlgorithms(this.aesCbc, this.hs256, this.kdfHs512);

            // when
            KeySet keys = this.secretsManager.GetSessionKeys(ref password, this.alg1);
            KeySet derivedKeys = this.secretsManager.DeriveSessionKeys(ref password, this.alg1, keys.salt);

            // then
            Assert.Equal(keys.encryptionKey, derivedKeys.encryptionKey);
            Assert.Equal(keys.validationKey, derivedKeys.validationKey);
            Assert.Equal(keys.salt, keys.salt);
        }

        [Fact]
        public void TestGetSessionKeysAesCbcHs512KdfHs256ValidDerivation()
        {
            // given
            string password = "NeverUseThisPasswo0rd12$34";
            this.alg1 = new CryptoAlgorithms(this.aesCbc, this.hs512, this.kdfHs256);

            // when
            KeySet keys = this.secretsManager.GetSessionKeys(ref password, this.alg1);
            KeySet derivedKeys = this.secretsManager.DeriveSessionKeys(ref password, this.alg1, keys.salt);

            // then
            Assert.Equal(keys.encryptionKey, derivedKeys.encryptionKey);
            Assert.Equal(keys.validationKey, derivedKeys.validationKey);
            Assert.Equal(keys.salt, keys.salt);
        }

        [Fact]
        public void TestGetSessionKeysAesCbcHs512KdfHs512ValidDerivation()
        {
            // given
            string password = "NeverUseThisPasswo0rd12$34";
            this.alg1 = new CryptoAlgorithms(this.aesCbc, this.hs512, this.kdfHs512);

            // when
            KeySet keys = this.secretsManager.GetSessionKeys(ref password, this.alg1);
            KeySet derivedKeys = this.secretsManager.DeriveSessionKeys(ref password, this.alg1, keys.salt);

            // then
            Assert.Equal(keys.encryptionKey, derivedKeys.encryptionKey);
            Assert.Equal(keys.validationKey, derivedKeys.validationKey);
            Assert.Equal(keys.salt, keys.salt);
        }

        [Fact]
        public void TestDeriveSessionKeysAesCbcHs512KdfHs512IncorrectSaltSize()
        {
            // given
            string password = "NeverUseThisPasswo0rd12$34";
            this.alg1 = new CryptoAlgorithms(this.aesCbc, this.hs512, this.kdfHs512);

            // when
            KeySet keys = this.secretsManager.GetSessionKeys(ref password, this.alg1);
            byte[] salt = new byte[keys.salt.Length - 1];
            Buffer.BlockCopy(keys.salt, 0, salt, 0, salt.Length);

            // then
            Assert.Throws<ArgumentException>(
                () =>
                    this.secretsManager.DeriveSessionKeys(ref password, this.alg1, salt)
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
            string password = null;
            Assert.Throws<ArgumentNullException>(
                () =>
                    this.secretsManager.Protect(ref password, this.alg2, "secretid", secret)
            );
        }

        [Fact]
        public void TestProtectNullAlgorithm()
        {
            byte[] secret = Enumerable.Repeat((byte)0x10, 16).ToArray();
            string password = "NeverUseThisPassword";
            Assert.Throws<ArgumentNullException>(
                () =>
                    this.secretsManager.Protect(ref password, null, "secretid", secret)
            );
        }


        [Fact]
        public void TestProtectNullSecretId()
        {
            byte[] secret = Enumerable.Repeat((byte)0x10, 16).ToArray();
            string password = "NeverUseThisPassword";
            Assert.Throws<ArgumentNullException>(
                () =>
                    this.secretsManager.Protect(ref password, this.alg2, null, secret)
            );
        }


        [Fact]
        public void TestProtectNullSecretBytes()
        {
            string password = "NeverUseThisPassword";
            Assert.Throws<ArgumentNullException>(
                () =>
                    this.secretsManager.Protect(ref password, this.alg2, "secretid", null)
            );
        }

        [Fact]
        public void TestProtectInvalidSecretIdLength()
        {
            byte[] secret = Enumerable.Repeat((byte)0x10, 16).ToArray();
            string password = "NeverUseThisPassword";
            byte[] secretIdBytes = Enumerable.Repeat((byte)0x10, this.secretsManager.maxSecretIdBytes + 1).ToArray();
            string secretId = StringUtils.GetString(secretIdBytes);
            Assert.Throws<ArgumentOutOfRangeException>(
                () =>
                    this.secretsManager.Protect(ref password, this.alg2, secretId, secret)
            );
        }

        [Fact]
        public void TestProtectInvalidSecretLength()
        {
            byte[] secret = Enumerable.Repeat((byte)0x10, this.secretsManager.maxSecretBytes + 1).ToArray();
            string password = "NeverUseThisPassword";
            string secretId = "secretId";

            Assert.Throws<ArgumentOutOfRangeException>(
                () =>
                    this.secretsManager.Protect(ref password, this.alg2, secretId, secret)
            );
        }

        [Fact]
        public void TestUnprotectNullPassword()
        {
            string password = null;
            Secret secret = new Secret("", "", "", "", "", DateTime.UtcNow, "", "");

            Assert.Throws<ArgumentNullException>(
                () =>
                    this.secretsManager.Unprotect(ref password, secret)
            );
        }


        [Fact]
        public void TestUnprotectNullSecret()
        {
            string password = "BadPassword";
            
            Assert.Throws<ArgumentNullException>(
                () =>
                    this.secretsManager.Unprotect(ref password, null)
            );
        }

        [Fact]
        public void TestUnprotectInvalidB64AlgIds()
        {
            string password = "BadPassword";
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
                    this.secretsManager.Unprotect(ref password, secret)
            );
        }

        [Fact]
        public void TestUnprotectInvalidB64Salt()
        {
            string password = "BadPassword";
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
                    this.secretsManager.Unprotect(ref password, secret)
            );
        }


        [Fact]
        public void TestUnprotectInvalidB64Iv()
        {
            string password = "BadPassword";
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
                    this.secretsManager.Unprotect(ref password, secret)
            );
        }


        [Fact]
        public void TestUnprotectInvalidB64Ciphertext()
        {
            string password = "BadPassword";
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
                    this.secretsManager.Unprotect(ref password, secret)
            );
        }


        [Fact]
        public void TestUnprotectInvalidB64Mac()
        {
            string password = "BadPassword";
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
                    this.secretsManager.Unprotect(ref password, secret)
            );
        }

    }
}