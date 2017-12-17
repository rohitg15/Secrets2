using System;
using Models;
using Xunit;
using System.Collections.Generic;

namespace Test
{
    public class VaultTest
    {

        public Vault vault { get; set; }
        public Secret validSecret1 { get; set; }
        public Secret validSecret2 { get; set; }
        public Secret validSecret3 { get; set; }
        public VaultTest()
        {
            this.vault = new Vault("Test");
            this.validSecret1 = new Secret("secretId", "b64EncryptedSecret", "b64Salt", DateTime.UtcNow, DateTime.UtcNow, "tag", "mac");
            this.validSecret2 = new Secret("secretId", "b64EncryptedSecret", "b64Salt", DateTime.UtcNow, DateTime.UtcNow, "tag", "mac");
            this.validSecret3 = new Secret("secretId3", "b64EncryptedSecret", "b64Salt", DateTime.UtcNow, DateTime.UtcNow, "tag", "mac");
        }

        [Fact]
        public void TestVaultNullName()
        {
            Assert.Throws<ArgumentNullException>(
                () =>
                    new Vault(null)
            );
        }

        [Fact]
        public void TestVaultEmptyName()
        {
            Assert.Throws<ArgumentException>(
                () =>
                    new Vault("")
            );
        }

        [Fact]
        public void TestAddSecretNull()
        {
            var vault = new Vault("test");
            Secret secret = null;
            Assert.Throws<ArgumentNullException>(
                () =>
                    vault.AddSecret(ref secret)
            );
        }

        [Fact]
        public void TestRemoveSecretNull()
        {
            var vault = new Vault("test");
            string secretId = null;
            Assert.Throws<ArgumentNullException>(
                () =>
                    vault.RemoveSecret(ref secretId)
            );
            
        }

        [Fact]
        public void TestAddSecretRemoveSecret()
        {
            var vault = new Vault("test");
            string secretId = this.validSecret1.secretId;
            var secret1 = this.validSecret1;
            vault.AddSecret(ref secret1);

            Assert.Equal(1, vault.GetNumSecrets());

            vault.RemoveSecret(ref secretId);
            Assert.Equal(0, vault.GetNumSecrets());
        }

        [Fact]
        public void TestAddSecretGetSecretByTag()
        {
            var vault = new Vault("test");
            string tag1 = this.validSecret1.tag;
            string tag3 = this.validSecret3.tag;

            string secretId1 = this.validSecret1.secretId;
            string secretId3 = this.validSecret3.secretId;

            Assert.Equal(tag1, tag3);

            // when
            var secret1 = this.validSecret1;
            var secret3 = this.validSecret3;
            vault.AddSecret(ref secret1);
            vault.AddSecret(ref secret3);

            ICollection<Secret> secretsByTag = vault.GetSecretsByTag(tag1);
            
            // then
            Assert.Equal(2, secretsByTag.Count);
            Assert.Equal(2, vault.GetNumSecrets());

            foreach (var secretItem in secretsByTag)
            {
                if (secretItem.secretId.Equals(secretId1))
                {
                    Assert.Equal(this.validSecret1, secretItem);
                }
                else if (secretItem.secretId.Equals(secretId3))
                {
                    Assert.Equal(this.validSecret3, secretItem);
                }
                else
                {
                    Assert.True(1 == 0);
                }
            }      
        }

        [Fact]
        public void TestRemoveSecretWithoutAdd()
        {
            var vault = new Vault("test");

            // when
            string secretId = this.validSecret1.secretId;
            
            // then
            Assert.Throws<KeyNotFoundException>(
                () =>
                    vault.RemoveSecret(ref secretId)
            );
        }

        [Fact]
        public void TestGetSecretByTagWithoutAdd()
        {
            var vault = new Vault("test");

            // when
            string tag = this.validSecret1.tag;

            // then
            Assert.Throws<KeyNotFoundException>(
                () =>
                    vault.GetSecretsByTag(tag)
            );
        }

        [Fact]
        public void TestSecretByTagAfterRemove()
        {
            var vault = new Vault("test");
            string tag = this.validSecret1.tag;
            var secret1 = this.validSecret1;
            var secret3 = this.validSecret3;

            // when
            vault.AddSecret(ref secret1);
            vault.AddSecret(ref secret3);
            ICollection<Secret> secretsByTag = vault.GetSecretsByTag(tag);

            // then
            Assert.Equal(2, secretsByTag.Count);

            // when
            string secretId1 = this.validSecret1.secretId;
            vault.RemoveSecret(ref secretId1);

            // then
            Assert.Equal(1, vault.GetNumSecrets());
            ICollection<Secret> secretsByTagUpdated = vault.GetSecretsByTag(tag);
            Assert.Equal(1, secretsByTagUpdated.Count);
            foreach (var item in secretsByTagUpdated)
            {
                Assert.Equal(this.validSecret3, item);
            }

            // when
            string secretId3 = this.validSecret3.secretId;
            vault.RemoveSecret(ref secretId3);

            // then
            Assert.Throws<KeyNotFoundException>(
                () =>
                    vault.GetSecretsByTag(tag)
            );
        }

        [Fact]
        public void TestAddSecretTwoCollidingSecrets()
        {
            var vault = new Vault("test");
            var secret1 = this.validSecret1;
            var secret2 = this.validSecret2;
            
            // when
            vault.AddSecret(ref secret1);
            Assert.Throws<ArgumentException>(
                () =>
                    vault.AddSecret(ref secret2)
            );

            ICollection<Secret> retrievedSecret = vault.GetSecretsByTag(secret1.tag);
            Assert.Equal( 1 , retrievedSecret.Count);
            var secretId = secret1.secretId;
            vault.RemoveSecret(ref secretId);
            Assert.Throws<KeyNotFoundException>(
                () =>
                    vault.RemoveSecret(ref secretId)
            );
        }
    }
}