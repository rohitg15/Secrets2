using Models;
using System.IO;
using Crypto;
using Newtonsoft.Json;
using Utils;
using System;
using System.Collections.Generic;

namespace Dal
{
    
    public class FileStorage : IStorage
    {
        private string rootDir;

        public FileStorage(string rootDir)
        {
            Preconditions.CheckNotNull(rootDir);
            this.rootDir = rootDir;
        }

        public Secret ReadSecret(string secretId)
        {
            Preconditions.CheckNotNull(secretId);

            byte[] digestBytes = StringUtils.GetBytes(HashProvider.GetSha256Digest(secretId));
            string fileName = "." + StringUtils.GetHexFromBytes(digestBytes) + ".json";
            string secretData = null;
            Secret secret = null;

            try
            {
                string filePath = Path.Combine(this.rootDir, fileName);
                secretData = File.ReadAllText(filePath);
            }
            catch (System.Exception)
            {
                throw new System.Exception("secret not found!");
            }

            try
            {
                secret = JsonConvert.DeserializeObject<Secret>(secretData);
            }
            catch(System.Exception)
            {
                throw new System.Exception("Internal Error. Corrupted database");
            }
            return secret;
        }

        public void WriteSecret(Secret secret)
        {
            Preconditions.CheckNotNull(secret);

            byte[] digestBytes = StringUtils.GetBytes(HashProvider.GetSha256Digest(secret.secretId));
            string fileName = "." + StringUtils.GetHexFromBytes(digestBytes) + ".json";
                
            try
            {
                string filePath = Path.Combine(this.rootDir, fileName);
                string secretData = JsonConvert.SerializeObject(secret);
                File.WriteAllText(filePath, secretData);
            }
            catch(System.Exception)
            {
                throw new System.Exception("Failed to write secret!");
            }
        }

        public List<Secret> ListSecrets()
        {
            throw new System.Exception("Not Implemented!");
        }
    }

}