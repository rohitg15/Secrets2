using System;
using Models;
using Crypto;
using Utils;
using Dal;
using Microsoft.Extensions.CommandLineUtils;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System.Collections.Generic;
using System.Security;
using System.Diagnostics;

namespace Secrets
{
    
    class Program
    {

        private static void AsciiArt()
        {
            Console.WriteLine();
            Console.WriteLine("========== Secrets ==========");
            Console.WriteLine();
            Console.WriteLine(@"     /===\          ^");
            Console.WriteLine(@"   -/ O   \++++++++++\");
            Console.WriteLine(@"  ==       ============>>>>o");
            Console.WriteLine(@"   -\ O   /++++++++++/  |||");
            Console.WriteLine(@"     \===/");
            Console.WriteLine();
        }

        private static SecretsManager InitSecretsManager()
        {
           return new SecretsManager(
               new AesHelper(),
               new MacHelper()
            );
        }

        private static CryptoAlgorithms InitAlgorithms()
        {
            return new CryptoAlgorithms(
                new EncryptionAlgorithm(EncryptionAlgorithmType.AES_CBC),
                new MacAlgorithm(MacAlgorithmType.HMAC_SHA512),
                new KdfAlgorithm(KeyDerivationPrf.HMACSHA512)
            );
        }

        private static IStorage InitStorage(string rootDir = "db")
        {
            return new FileStorage(rootDir);
        }

        private static void CopyToOsxClipboard(byte[] secretBytes)
        {
            string secretData = StringUtils.GetString(secretBytes);
            string cmd = String.Format("echo '{0}' | pbcopy", secretData);
            var process = new Process()
            {
                StartInfo = new ProcessStartInfo()
                {
                    FileName = "/bin/bash",
                    Arguments = $"-c \"{cmd}\"",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                } 
            };

            process.Start();
            process.WaitForExit();
            if (process.ExitCode != 0)
            {
                string result = process.StandardError.ReadToEnd();
                string errMsg = String.Format("Error copying output to clipboard: {0}", result);
                throw new System.Exception(errMsg);
            }
        }

        private static void DisplaySecret(byte[] secretBytes)
        {
            switch(OsUtils.GetCurrentPlatform())
            {
                case OsPlatform.OsX:
                {
                    CopyToOsxClipboard(secretBytes);
                    Console.WriteLine("Secret value copied to clipboard!");
                    break;
                }
                default:
                {
                    string secretData = StringUtils.GetString(secretBytes);
                    Console.WriteLine("Secret value > {0}", secretData);
                    break;
                }
            }
        }

        static void Main(string[] args)
        {
            string password = "";
            Console.Write("Enter Password:");
            SecureString passwd = StringUtils.ReadSecretString();
            password = passwd.ToString();
            Console.Write("\n");

            SecretsManager manager = InitSecretsManager();
            CryptoAlgorithms alg = InitAlgorithms();
            IStorage storageManager = InitStorage();

            int choice = 0;
            do
            {
                String helpStr = "========== help ==========\n";
                helpStr +=       "1. Display Secret Ids\n";
                helpStr +=       "2. Get Secret\n";
                helpStr +=       "3. Put Secret\n";
                helpStr +=       "4. Quit\n";

                AsciiArt();
                Console.WriteLine(helpStr);
                Console.Write(">>");
                choice = Int32.Parse(Console.ReadLine());

                switch (choice)
                {
                    case 1:
                    {
                        
                        List<Secret> secrets = storageManager.ListSecrets();
                        int count = 0;
                        Console.WriteLine();
                        Console.WriteLine("===== {0} secrets found =====", secrets.Count);
                        if  (secrets.Count == 0)
                        {
                            break;
                        }
                        foreach(Secret secret in secrets)
                        {
                            Console.WriteLine("{0}.{1}", ++count, secret.secretId);
                        }
                        Console.Write("\n");
                        break;
                    }
                    case 2:
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
                            break;
                        }

                        try
                        {
                            retrievedSecretBytes = manager.Unprotect(ref passwd, secret);
                        }
                        catch(Exception)
                        {
                            Console.WriteLine("Wrong Password. Secret Decryption failed!");
                            return;
                        }
                        DisplaySecret(retrievedSecretBytes);
                        Console.Write("\n");
                        break;
                    }
                    case 3:
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
                            secret = manager.Protect(ref passwd, alg, secretId, secretBytes, tag);
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
                        break;
                    }
                    default:
                    {
                        Console.WriteLine("===== Bye =====");
                        return;
                    }
                }
                
            } while (true);
        }
    }
}
