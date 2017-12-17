
using System;

namespace Utils
{
    public class StringUtils
    {
        public static byte[] GetBytes(string str)
        {
            Preconditions.CheckNotNull(str);
            byte[] bytes = new byte[str.Length * sizeof(char)];
            System.Buffer.BlockCopy(str.ToCharArray(), 0, bytes, 0, bytes.Length);
            return bytes;
        }

        public static string GetString(byte[] bytes)
        {
            Preconditions.CheckNotNull(bytes);
            char[] chars = new char[bytes.Length / sizeof(char)];
            System.Buffer.BlockCopy(bytes, 0, chars, 0, bytes.Length);
            return new string(chars);
        }

        public static string GetBase64String(byte[] bytes)
        {
            return Convert.ToBase64String(bytes);
        }

        public static byte[] GetBytesFromBase64(string b64Encoded)
        {
            return Convert.FromBase64String(Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes(b64Encoded)));
        }
    }
}