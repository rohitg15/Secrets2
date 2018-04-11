using System;

namespace Utils
{
    public class DisplayUtils
    {

        static readonly string helpStr = String.Format(
            "{0}\n{1},\n{2}\n{3}\n{4}\n{5}\n{6}",
            "========== help ==========",
            "1. Display Secret Ids",
            "2. Get Secret",
            "3. Put Secret",
            "4. Delete Secret",
            "5. Reset Session",
            "6. Quit Program"
        );
        public static void DisplayHelpStr()
        {
            Console.WriteLine(DisplayUtils.helpStr);
            Console.Write(">>");
        }

        public static void AsciiArt()
        {
            Console.WriteLine();
            Console.WriteLine("========== Secrets ==========");
            Console.WriteLine();
            Console.WriteLine(@"     /===\          ^");
            Console.WriteLine(@"   -/ O   \++++++++++\");
            Console.WriteLine(@"  ==       ============>>>>o");
            Console.WriteLine(@"   -\ O   /++++++++++/  |||");
            Console.WriteLine(@"     \===/");
            Console.WriteLine();
        }

        public static void DisplaySecret(byte[] secretBytes)
        {
            string cmd = "";
            string args = "";
            string exe = "";
            switch(OsUtils.GetCurrentPlatform())
            {
                case OsPlatform.OsX:
                {
                    string secretData = StringUtils.GetString(secretBytes);
                    cmd = String.Format("echo '{0}' | pbcopy", secretData);
                    exe = "/bin/bash";
                    args = $"-c \"{cmd}\"";
                    OsUtils.ExecuteCmd(exe, args);
                    Console.WriteLine("Secret value copied to clipboard!");
                    break;
                }
                case OsPlatform.Windows:
                {
                    string secretData = StringUtils.GetString(secretBytes);
                    cmd = String.Format("echo {0} | clip", secretData);
                    exe = "cmd.exe";
                    args = $"/c \"{cmd}\"";
                    OsUtils.ExecuteCmd(exe, args);
                    Console.WriteLine("Secret value copied to clipboard!");
                    break;
                }
                default:
                {
                    string secretData = StringUtils.GetString(secretBytes);
                    Console.WriteLine("Secret value > {0}", secretData);
                    break;
                }
            }
        }
    }
}
