
using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace Utils
{
    public class StringUtils
    {
        public static byte[] GetBytes(string str)
        {
            Preconditions.CheckNotNull(str);
            byte[] bytes = Encoding.ASCII.GetBytes(str);
            return bytes;
        }

        public static string GetString(byte[] bytes)
        {
            Preconditions.CheckNotNull(bytes);
            var encoding = Encoding.ASCII;
            char[] chars = encoding.GetChars(bytes);
            return new string(chars);
        }

        public static string GetBase64String(byte[] bytes)
        {
            return Convert.ToBase64String(bytes);
        }

        public static byte[] GetBytesFromBase64(string b64Encoded)
        {
            return Convert.FromBase64String(b64Encoded);
        }

        public static string GetHexFromBytes(byte[] bytes)
        {
            string hexStr = BitConverter.ToString(bytes);
            return hexStr.Replace("-", "");
        }

        public static byte[] GetBytesFromHex(string hexStr)
        {
            return Enumerable.Range(0, hexStr.Length)
                     .Where(x => x % 2 == 0)
                     .Select(x => Convert.ToByte(hexStr.Substring(x, 2), 16))
                     .ToArray();
        }

        public static string GetStringFromSecureString(SecureString secretString)
        {
            IntPtr stringPointer = Marshal.SecureStringToBSTR(secretString);
            string normalString = Marshal.PtrToStringBSTR(stringPointer);
            Marshal.ZeroFreeBSTR(stringPointer);
            return normalString;
        }

        public static SecureString ReadSecretString()
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
            password.MakeReadOnly();
            return password;
        }
    }
}