using System;
using Crypto;
using System.Security.Cryptography;
using Utils;

namespace Secrets
{
    
    class Program
    {
        static void Main(string[] args)
        {
            var csprng = RandomNumberGenerator.Create();
            EncryptionAlgorithm cryptoAlgorithm = new EncryptionAlgorithm(EncryptionAlgorithmType.AES_CBC);
            byte[] key = new byte[cryptoAlgorithm.keySizeBits / 8];
            byte[] iv = new byte[cryptoAlgorithm.blockSizeBits / 8];
            csprng.GetBytes(key, 0, key.Length);
            csprng.GetBytes(iv, 0, iv.Length);

            
            IEncryptionHelper cryptoService = new AesHelper();
            cryptoService.Init(cryptoAlgorithm, key, iv);
            string plaintext = "Hello World!";
            byte[] plaintextBytes = StringUtils.GetBytes(plaintext);
            byte[] ciphertext = cryptoService.EncryptBytesAsync(plaintextBytes).GetAwaiter().GetResult();

            byte[] newPlaintext = cryptoService.DecryptBytesAsync(ciphertext).GetAwaiter().GetResult();

            string newPlaintextString = StringUtils.GetString(newPlaintext);


            if (plaintext.Equals(newPlaintextString))
            {
                Console.WriteLine("Success!");
                Console.WriteLine("length 0 : {0}", plaintext.Length);
                Console.WriteLine("length 1 : {0}", newPlaintextString.Length);
            }
            else
            {
                Console.WriteLine("length 0 : {0}", plaintext.Length);
                Console.WriteLine("length 1 : {0}", newPlaintextString.Length);
                Console.WriteLine(String.Format("plaintext0 : {0}\nplaintext1 : {1}", plaintext, newPlaintextString));
            }

            Console.WriteLine("Hello World!");
        }
    }
}
