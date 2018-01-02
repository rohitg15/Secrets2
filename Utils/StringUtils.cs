
using System;
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
    }
}