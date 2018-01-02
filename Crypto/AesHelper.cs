using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Utils;

namespace Crypto
{
    public class AesHelper : IEncryptionHelper, IDisposable
    {
        public Aes cipher { get; set; } 

        public AesHelper()
        {
            this.cipher = Aes.Create();
        }
        public byte[] EncryptBytes(byte[] plaintext)
        {
            Preconditions.CheckNotNull(plaintext);

            using(MemoryStream ciphertextStream = new MemoryStream())
            {
                using(CryptoStream cryptoStream = new CryptoStream(ciphertextStream,
                                                                   this.cipher.CreateEncryptor(),
                                                                   CryptoStreamMode.Write
                                                                    ))
                {
                    cryptoStream.Write(plaintext, 0, plaintext.Length);
                }
                return ciphertextStream.ToArray();
            }
        }

        public byte[] DecryptBytes(byte[] ciphertext)
        {
            Preconditions.CheckNotNull(ciphertext);

            using(MemoryStream plainStream = new MemoryStream())
            {
                using(CryptoStream cryptoStream = new CryptoStream(plainStream,
                                                                    this.cipher.CreateDecryptor(),
                                                                    CryptoStreamMode.Write))
                {
                    cryptoStream.Write(ciphertext, 0, ciphertext.Length);
                }
                return plainStream.ToArray();
            }
        }

        public void Init(EncryptionAlgorithm algorithm, byte[] key, byte[] iv)
        {
            Preconditions.CheckNotNull(algorithm);
            Preconditions.CheckNotNull(key);
            Preconditions.CheckNotNull(iv);

            if ( (key.Length * 8 != algorithm.keySizeBits) || (iv.Length * 8 != algorithm.blockSizeBits) )
            {
                string msg = String.Format(
                                            "Invalid crypto parameter lengths.",
                                            "Expected iv {0} bits and key {1} bits.", 
                                            "Got iv {2} bits and key {3} bits.",
                                            algorithm.blockSizeBits,
                                            algorithm.keySizeBits,
                                            key.Length,
                                            iv.Length
                                            );
                throw new CryptographicException(msg);
            }
            switch (algorithm.algorithmType)
            {
                case EncryptionAlgorithmType.AES_CBC:
                {
                    this.cipher.Mode = CipherMode.CBC;
                    this.cipher.Padding = PaddingMode.PKCS7;
                    break;
                }
                default:
                {
                    string msg = String.Format("Unsupported rncryption algorithm {0}",
                                                algorithm.algorithmType);
                    throw new CryptographicException(msg);
                }
            }
            this.cipher.Key = key;
            this.cipher.IV = iv;
        }

        #region IDisposable Support
        private bool disposedValue = false; // To detect redundant calls

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    // TODO: dispose managed state (managed objects).
                    // TODO: Securely erase contents of key if possible
                   this.cipher.Dispose();
                   this.cipher = null;
                }

                // TODO: free unmanaged resources (unmanaged objects) and override a finalizer below.
                // TODO: set large fields to null.

                disposedValue = true;
            }
        }

        // TODO: override a finalizer only if Dispose(bool disposing) above has code to free unmanaged resources.
        // ~AesEncryptor() {
        //   // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
        //   Dispose(false);
        // }

        // This code added to correctly implement the disposable pattern.
        public void Dispose()
        {
            // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
            Dispose(true);
            // TODO: uncomment the following line if the finalizer is overridden above.
            // GC.SuppressFinalize(this);
        }
        #endregion
    }
}