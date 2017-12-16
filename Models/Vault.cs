using System;
using System.Collections.Generic;
using Utils;

namespace Models
{
    public class Vault
    {
        public string vaultName { get; set; }

        public Dictionary<string, Secret> secrets { get; set; }

        public Dictionary<string, List<string> > tagIndex { get; set; }

        public Vault(string name)
        {
            this.vaultName = Preconditions.CheckNotNull(name);
            this.secrets = new Dictionary<string, Secret>();
            this.tagIndex = new Dictionary<string, List<string> >();
        }

        public void AddSecret(ref Secret secret)
        {
            Preconditions.CheckNotNull(secret);

            this.secrets.Add(secret.secretId, secret);
            if ( !this.tagIndex.ContainsKey(secret.tag) )
            {
                this.tagIndex[secret.tag] = new List<string>();
            }
            this.tagIndex[secret.tag].Add(secret.secretId);
        }

        public void RemoveSecret(ref string secretId)
        {
            Preconditions.CheckNotNull(secretId);

            if( this.secrets.ContainsKey(secretId) )
            {
                Secret secret = this.secrets[secretId];

                this.tagIndex[secret.tag].Remove(secret.secretId);
                if (this.tagIndex[secret.tag].Count == 0)
                {
                    this.tagIndex.Remove(secret.tag);
                }
                this.secrets.Remove(secretId);
                return ;
            }
            throw new KeyNotFoundException(String.Format("Secret with id {0} not found", secretId));
        }

        public IEnumerable<Secret> getSecretsByTag(string tag)
        {
            Preconditions.CheckNotNull(tag);

            if ( this.tagIndex.ContainsKey(tag) )
            {
                IEnumerable<string> secretIds = this.tagIndex[tag];
                List<Secret> tagSecrets = new List<Secret>();
                foreach (var id in secretIds)
                {
                    tagSecrets.Add(this.secrets[id]);
                }
                return tagSecrets;
            }
            throw new KeyNotFoundException(String.Format("Tag with name {0} was not found", tag));
        }
    }
}