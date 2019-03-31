using System;
using Models;
using System.Linq;
using System.Collections.Generic;
using System.Security;
using Utils;
using Newtonsoft.Json;
using Dropbox.Api.Files;
using System.Threading.Tasks;

namespace Dal
{

    public class DropboxStorage : IStorage
    {

        public DropboxStorage(SecureString accessToken, string rootFolderName = "/SecretDb")
        {
            this.dbx_ = new DropboxUtil(accessToken);
            this.rootFolderName_ = rootFolderName;

        }

        public string GetProviderName()
        {
            return "Dropbox";
        }

        public async Task<List<Secret>> GetSecretsAsync(List<Secret> localSecrets)
        {
            Dictionary<string, bool> localFileNames = new Dictionary<string, bool>();
            foreach(Secret localSecret in localSecrets)
            {
                string localSecretId = localSecret.secretId;
                byte[] digestBytes = StringUtils.GetBytes(HashProvider.GetSha256Digest(localSecretId));
                string localFileName = "." + StringUtils.GetHexFromBytes(digestBytes) + ".json";
                localFileNames.Add(localFileName, true);
            }

            // List remote files
            List<Metadata> fileInfos = await dbx_.ListRootFolder(rootFolderName_);

            List<Secret> remoteSecrets = new List<Secret>();
            // Download delta from cloud provider
            foreach(var fileInfo in fileInfos)
            {
                if (localFileNames.ContainsKey(fileInfo.Name) == false)
                {
                    // Download this locally
                    string content = await dbx_.Download(rootFolderName_, fileInfo.Name);
                    Secret secret = null;
                    try
                    {
                        secret = JsonConvert.DeserializeObject<Secret>(content);
                    }
                    catch(System.Exception)
                    {
                        Console.WriteLine("Failed to deserialize remote secret - " + fileInfo.Name + " for " + GetProviderName());
                        throw;
                    }
                    remoteSecrets.Add(secret);
                }
            }
            return remoteSecrets;
        }

        public void DeleteSecret(string secretId)
        {
            Preconditions.CheckNotNull(secretId);
            byte[] digestBytes = StringUtils.GetBytes(HashProvider.GetSha256Digest(secretId));
            string remoteFileName = "." + StringUtils.GetHexFromBytes(digestBytes) + ".json";
            dbx_.DeleteFile(rootFolderName_, remoteFileName);
        }

        public List<Secret> ListSecrets()
        {
            dbx_.ListRootFolder(rootFolderName_).Wait();
            return null;
        }

        public Secret ReadSecret(string secretId)
        {
            throw new NotImplementedException();
        }

        public void WriteSecret(Secret secret, bool overwrite = false)
        {
            Preconditions.CheckNotNull(secret);
            byte[] digestBytes = StringUtils.GetBytes(HashProvider.GetSha256Digest(secret.secretId));
            string remoteFileName = "." + StringUtils.GetHexFromBytes(digestBytes) + ".json";
                
            // To Do - If file with same name already exists in dtopbox,
            // check content hash to avoid unnecessary write.

            try
            {
                string secretData = JsonConvert.SerializeObject(secret);
                this.dbx_.Upload(rootFolderName_, remoteFileName, secretData).Wait();
            }
            catch(System.Exception)
            {
                 throw new System.Exception("Failed to write secret for provider - " + GetProviderName());
            }
            
        }

        private DropboxUtil dbx_;
        private string rootFolderName_;
    }
}