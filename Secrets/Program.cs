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
using System.Text;

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

        private static IStorage InitStorage(string rootDir = "db")
        {
            return new FileStorage(rootDir);
        }

        static void Main(string[] args)
        {
            bool resetSession = false;
            do 
            { 
                DisplayUtils.AsciiArt();
                SecretsManager secretsManager = InitSecretsManager();
                CryptoAlgorithms algs = InitAlgorithms();
                IStorage storageManager = InitStorage();
                SessionManager sessionManager = new SessionManager(
                                                                    InitSecretsManager(),
                                                                    InitAlgorithms(), 
                                                                    InitStorage()
                                                                );  
                try
                {
                    resetSession = false;
                    sessionManager.StartSession();
                    sessionManager.Repl(out resetSession);
                }
                finally
                {
                    sessionManager.ExitSession();
                }
            } while (resetSession);
        }
    }
}
