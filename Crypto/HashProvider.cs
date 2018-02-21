

using System.Security.Cryptography;
using Utils;

public class HashProvider
{
    public static string GetSha256Digest(string data)
    {
        using (var algorithm = SHA256.Create())
        {
            byte[] hashBytes = algorithm.ComputeHash(StringUtils.GetBytes(data));
            return StringUtils.GetString(hashBytes);
        }
    }
}