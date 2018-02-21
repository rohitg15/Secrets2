using System;
using Models;
using Crypto;
using Utils;
using Dal;
using Microsoft.Extensions.CommandLineUtils;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System.Collections.Generic;
using System.Security;

namespace Secrets
{
    
    class Program
    {

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

        private static IStorage InitStorage(string rootDir = ".")
        {
            return new FileStorage(rootDir);
        }

        private static SecureString ReadPassword()
        {    
            var password = new SecureString();
            while (true)
            {
                ConsoleKeyInfo i = Console.ReadKey(true);
                if (i.Key == ConsoleKey.Enter)
                {
                    break;
                }
                else if (i.Key == ConsoleKey.Backspace)
                {
                    if (password.Length > 0)
                    {
                        password.RemoveAt(password.Length - 1);
                        Console.Write("\b \b");
                    }
                }
                else
                {
                    password.AppendChar(i.KeyChar);
                    Console.Write("*");
                }
            }
            return password;
        }

        static void Main(string[] args)
        {

            String helpStr = "---------- Secrets ----------\n";
            helpStr +=       "1. Display Secret Ids\n";
            helpStr +=       "2. Get Secret\n";
            helpStr +=       "3. Put Secret\n";
            helpStr +=       "4. Quit\n";

            string password = "";
            Console.Write("Enter Password:");
            SecureString passwd = ReadPassword();
            password = passwd.ToString();
            Console.Write("\n");

            SecretsManager manager = InitSecretsManager();
            CryptoAlgorithms alg = InitAlgorithms();
            IStorage storageManager = InitStorage();

            int choice = 0;
            do
            {
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
                        Console.Write("\n");

                        Secret secret = storageManager.ReadSecret(secretId);
                        byte[] retrievedSecretBytes = manager.Unprotect(passwd, secret);
                        string secretData = StringUtils.GetString(retrievedSecretBytes);
                        Console.WriteLine("Secret value > {0}", secretData);
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
                        string secretStr = Console.ReadLine();
                        Console.Write("\n");

                        Console.Write("Enter tag(optional)");
                        string tag = Console.ReadLine();
                        if (String.IsNullOrEmpty(tag))
                        {
                            tag = "Default";
                        }
                        // check size
                        byte[] secretBytes = StringUtils.GetBytes(secretStr);
                        Secret secret = manager.Protect(passwd, alg, secretId, secretBytes, tag);

                        // write secret to persistent storage
                        storageManager.WriteSecret(secret);
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
