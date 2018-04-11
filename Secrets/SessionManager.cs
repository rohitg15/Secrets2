using Crypto;
using Dal;
using Utils;
using System;
using System.Collections.Generic;
using Models;
using System.Security;

namespace Secrets
{
    public class SessionManager
    {
        private SecretsManager secretsManager;
        private CryptoAlgorithms algs;
        private IStorage storageManager;

        private SecureString passwd;

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
        }

        public void StartSession()
        {
            Console.WriteLine(sessionDisplay);
            Console.Write("Enter Password:");
            this.passwd = StringUtils.ReadSecretString();
            Console.Write("\n\n");
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
                    default:
                    {
                        Console.WriteLine("===== Bye =====");
                        return;
                    }
                }
                DisplayUtils.AsciiArt();
                
            } while (true);
        }

        public void ListSecrets()
        {
                        
            List<Secret> secrets = storageManager.ListSecrets();
            int count = 0;
            Console.WriteLine();
            Console.WriteLine("===== {0} secrets found =====", secrets.Count);
            if  (secrets.Count != 0)
            {
                foreach(Secret secret in secrets)
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
                // write secret to persistent storage
                storageManager.WriteSecret(secret);
            }
            catch(Exception)
            {
                Console.WriteLine("Error: Could not store secret!");
                return;
            }
            Console.WriteLine("Stored Secret successfully!");
            Console.Write("\n");
        }

        public void DeleteSecret()
        {
            Console.Write("Enter secret id (it will be deleted permanently):");
            string secretId = Console.ReadLine();
            storageManager.DeleteSecret(secretId);
        }

        public void ExitSession()
        {
            this.passwd.Dispose();;
        }
    }
}