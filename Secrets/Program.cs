using System;
using Models;
using Crypto;
using Utils;
using Microsoft.Extensions.CommandLineUtils;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;


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

        static void Main(string[] args)
        {

            String helpStr = "---------- Secrets ----------\n";
            helpStr +=       "1. Display Secret Ids\n";
            helpStr +=       "2. Get Secret\n";
            helpStr +=       "3. Put Secret\n";
            helpStr +=       "4. Quit\n";

            string password = "";
            Console.Write("Enter Password:");
            password = Console.ReadLine();
            Console.Write("\n");

            SecretsManager manager = InitSecretsManager();
            CryptoAlgorithms alg = InitAlgorithms();

            int choice = 0;
            do
            {
                Console.WriteLine(helpStr);
                Console.Write(">");
                choice = Console.Read();

                switch (choice)
                {
                    case 1:
                    {
                        
                        break;
                    }
                    case 2:
                    {
                        Console.Write("Enter Secret id:");
                        string secretId = Console.ReadLine();
                        Console.Write("\n");


                        break;
                    }
                    case 3:
                    {
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
                        Secret secret = manager.Protect(ref password, alg, secretId, secretBytes, tag);

                        // write secret to persistent storage
                        break;
                    }
                    default:
                    {
                        return;
                    }
                }
                
            } while (true);


        }
    }
}
