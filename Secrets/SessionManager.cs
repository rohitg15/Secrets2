using Crypto;
using Dal;
using Utils;
using System;
using System.Collections.Generic;
using Models;
using System.Security;
using System.Threading.Tasks;

namespace Secrets
{
    public class SessionManager
    {
        private SecretsManager secretsManager;
        private CryptoAlgorithms algs;
        private IStorage storageManager;

        private DropboxStorage cloudStorageManager;

        private SecureString passwd;

        List<Secret> localSecrets_;
        private static readonly string sessionDisplay = String.Format(
                "<<<<<<<<<< Starting new Session >>>>>>>>>>\n # {0}\n # {1}", 
                "Enter old password to restore previous session and retrieve secrets stored in that session OR",
                "Enter a new password to start a completely new session. Previous secrets cannot be retrieved"
            );
        public SessionManager(SecretsManager secretsManager, CryptoAlgorithms algs, IStorage storageManager)
        {
            this.secretsManager = Preconditions.CheckNotNull(secretsManager);
            this.algs = Preconditions.CheckNotNull(algs);
            this.storageManager = Preconditions.CheckNotNull(storageManager);
            this.localSecrets_ = new List<Secret>();
           
        }

        public void StartSession()
        {
            Console.WriteLine(sessionDisplay);
            Console.Write("Enter Password:");
            this.passwd = StringUtils.ReadSecretString();
            Console.Write("\n\n");
            InitializeCloudStorage();
        }

        public void Repl(out bool resetSession)
        {
            do
            {
                int choice = 0;
                resetSession = false;
                DisplayUtils.DisplayHelpStr();
                if (false == Int32.TryParse(Console.ReadLine(), out choice))
                {
                    Console.WriteLine("Oops: only numbers in the display are allowed\n");
                    continue;
                }
                
                switch (choice)
                {
                    case 1:
                    {
                        this.ListSecrets();
                        break;
                    }
                    case 2:
                    {
                        this.GetSecret();
                        break;
                    }
                    case 3:
                    {
                        this.PutSecret();
                        break;
                    }
                    case 4:
                    {
                        this.DeleteSecret();
                        break;
                    }
                    case 5:
                    {
                        resetSession = true;
                        Console.WriteLine("<<<<<<<<<< Ending current Session >>>>>>>>>>");
                        return;
                    }
                    case 6:
                    {
                        this.UploadLocalSecrets();
                        break;
                    }
                    default:
                    {
                        Console.WriteLine("===== Bye =====");
                        return;
                    }
                }
                DisplayUtils.AsciiArt();
                
            } while (true);
        }

        private void InitializeLocalSessionSecrets()
        {
            if (localSecrets_.Count == 0)
            {
                List<Secret> secrets = storageManager.ListSecrets();
                localSecrets_.AddRange(secrets);
            }
            PersistRemoteSecrets(localSecrets_).Wait();
        }

        public async Task PersistRemoteSecrets(List<Secret> localSecrets)
        {
             // List remote secrets
            List<Secret> remoteSecrets = await this.cloudStorageManager.GetSecretsAsync(localSecrets);
            
            localSecrets_.AddRange(remoteSecrets);

            // persist remote secrets locally
            foreach(var remoteSecret in remoteSecrets)
            {
                Console.WriteLine(remoteSecret.secretId);
                this.storageManager.WriteSecret(remoteSecret);
            }
        }

        public void ListSecrets()
        {
            InitializeLocalSessionSecrets();

            int count = 0;
            Console.WriteLine();
            Console.WriteLine("===== {0} secrets found =====", localSecrets_.Count);
            
            // sort based on secret id - test and avoid copy if possible
            var localSecrets = new List<Secret>(localSecrets_);
            localSecrets.Sort(delegate(Secret a, Secret b){
                return a.secretId.CompareTo(b.secretId);
            });

            if  (localSecrets.Count != 0)
            {
                foreach(Secret secret in localSecrets)
                {
                    Console.WriteLine("{0}.{1}", ++count, secret.secretId);
                }
                Console.Write("\n");
            }
        }

        public void GetSecret()
        {
            Console.WriteLine();
            Console.WriteLine("===== Get Secret =====");
            Console.Write("Enter Secret id:");
            string secretId = Console.ReadLine();
            
            Secret secret = null;
            byte[] retrievedSecretBytes = null;
            try
            {
                secret = storageManager.ReadSecret(secretId);
            }
            catch(Exception)
            {
                Console.WriteLine("Secret with id {0} not found in db.", secretId);
                return;
            }

            try
            {
                retrievedSecretBytes = secretsManager.Unprotect(ref this.passwd, secret);
            }
            catch(Exception)
            {
                Console.WriteLine("Wrong Password. Secret Decryption failed!");
                return;
            }
            DisplayUtils.DisplaySecret(retrievedSecretBytes);
            Console.Write("\n");
        }

        public void PutSecret()
        {
            Console.WriteLine();
            Console.WriteLine("===== Store Secret =====");
            Console.Write("Enter Secret id:");
            string secretId = Console.ReadLine();
            Console.Write("\n");

            Console.Write("Enter Secret:");
            SecureString secretString = StringUtils.ReadSecretString();
            string secretStr = StringUtils.GetStringFromSecureString(secretString);
            Console.Write("\n");

            Console.Write("Enter tag(optional):");
            string tag = Console.ReadLine();
            if (String.IsNullOrEmpty(tag))
            {
                tag = "Default";
            }
            // check size
            byte[] secretBytes = StringUtils.GetBytes(secretStr);
            Secret secret = null;
            
            try
            {
                secret = secretsManager.Protect(ref this.passwd, algs, secretId, secretBytes, tag);
                
                // write secret to storage layers
                
                this.cloudStorageManager.WriteSecret(secret, true);
                Console.WriteLine("Stored Secret successfully in - " + this.cloudStorageManager.GetProviderName());
                
                this.storageManager.WriteSecret(secret);
                Console.WriteLine("Stored Secret successfully in - " + this.storageManager.GetProviderName());
                
            }
            catch(Exception)
            {
                Console.WriteLine("Error: Could not store secret!");
                return;
            }
            this.localSecrets_.Add(secret);
            Console.Write("\n");
        }

        public void DeleteSecret()
        {
            Console.Write("Enter secret id (it will be deleted permanently):");
            string secretId = Console.ReadLine();
            storageManager.DeleteSecret(secretId);
            this.cloudStorageManager.DeleteSecret(secretId);
            Console.WriteLine("Removed Secret : {0}", secretId);
                
            Secret item = this.localSecrets_.Find(s => s.secretId == secretId);
            if (item == null)
            {
                Console.WriteLine("Couldn't read secret from hash localSecrets_");
            }
            this.localSecrets_.Remove(item);
        
        }

        public void InitializeCloudStorage()
        {
            Console.WriteLine("Searching for Cloud Provider Secret");
            string secretId = "dropbox_access_token";
            Secret secret = null;
            byte[] retrievedSecretBytes = null;
            try
            {
                secret = storageManager.ReadSecret(secretId);
            }
            catch(Exception)
            {
                Console.WriteLine("Secret with id {0} not found in db. Insert access token with id {1} to enable dropbox sync", secretId, secretId);
                return;
            }

            try
            {
                retrievedSecretBytes = secretsManager.Unprotect(ref this.passwd, secret);
            }
            catch(Exception)
            {
                Console.WriteLine("Wrong Password. Secret Decryption failed!");
                return;
            }
            SecureString accessToken = StringUtils.ToSecureString(StringUtils.GetString(retrievedSecretBytes));
                    
            this.cloudStorageManager = new DropboxStorage(accessToken);
            Console.WriteLine("Initialized provider : {0}", this.cloudStorageManager.GetProviderName());
        }

        public void UploadLocalSecrets()
        {
            List<Secret> secrets = storageManager.ListSecrets();
            foreach(var secret in secrets)
            {
                this.cloudStorageManager.WriteSecret(secret, true);
                Console.WriteLine("Uploaded secret : {0} to provider : {1}", secret.secretId, this.cloudStorageManager.GetProviderName());
            }
        }

        public void ExitSession()
        {
            this.passwd.Dispose();;
        }
    }
}