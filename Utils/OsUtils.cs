using System;
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

        
        public static void ExecuteCmd(string exe, string args)
        {
            Preconditions.CheckNotNull(exe);
            Preconditions.CheckNotNull(args);

            var process = new Process()
            {
                // shell execute must always be false
                // secret data is integrity protected, which prevents attacker from injecting
                // arbitrary commands in the db to gain code execution
                StartInfo = new ProcessStartInfo()
                {
                    FileName = exe,
                    Arguments = args,
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                } 
            };

            process.Start();
            process.WaitForExit();
            if (process.ExitCode != 0)
            {
                string result = process.StandardError.ReadToEnd();
                string errMsg = String.Format("Error copying output to clipboard: {0}", result);
                throw new System.Exception(errMsg);
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