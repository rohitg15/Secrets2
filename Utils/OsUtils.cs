using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Utils
{
    public class OsUtils
    {
        public static bool IsOsx()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.OSX);
        }

        public static bool IsLinux()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Linux);
        }

        public static bool IsWindows()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
        }

        public static OsPlatform GetCurrentPlatform()
        {
            if (OsUtils.IsOsx())
            {
                return OsPlatform.OsX;
            }
            else if (OsUtils.IsLinux())
            {
                return OsPlatform.Linux;
            }
            else if (OsUtils.IsWindows())
            {
                return OsPlatform.Windows;
            }
            else
            {
                throw new System.Exception("Unknown OS platform");
            }
        }
    }

    public enum OsPlatform
    {
        OsX,
        Linux,
        Windows
    }
}