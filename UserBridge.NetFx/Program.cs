using System;
using System.Diagnostics;
using System.Security.Principal;
using UserBridge.Core;

namespace UserBridge.NetFx
{
    internal class Program
    {
        private const int EXIT_SUCCESS = 0;
        private const int EXIT_ACCESS_DENIED = 1;
        private const int EXIT_RUNTIME_ERROR = 2;

        static void Main()
        {
            AppDomain.CurrentDomain.UnhandledException += (s, e) => { try { EventLog.WriteEntry("BridgeExec", $"未処理例外: {e.ExceptionObject}", EventLogEntryType.Error); } catch { } Environment.Exit(EXIT_RUNTIME_ERROR); };

            try
            {
                using (var id = WindowsIdentity.GetCurrent())
                {
                    var isSystem = string.Equals(id.Name, "NT AUTHORITY\\SYSTEM", StringComparison.OrdinalIgnoreCase);
                    var isAdmin = new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
                    if (!(isSystem || isAdmin)) { Console.Error.WriteLine($"Access denied: 実行ユーザー={id.Name}"); Environment.Exit(EXIT_ACCESS_DENIED); }
                }

                string cscript = Environment.ExpandEnvironmentVariables(@"%SystemRoot%\\System32\\cscript.exe");
                string script = @"C:\\Scripts\\myscript.vbs";
                ProcessLauncher.RunForActiveUser($"\"{cscript}\" //nologo \"{script}\"", @"C:\\Scripts");
                Console.WriteLine("起動要求OK");
                Environment.Exit(EXIT_SUCCESS);
            }
            catch (Exception ex)
            {
                try { EventLog.WriteEntry("BridgeExec", $"実行エラー: {ex}", EventLogEntryType.Error); } catch { }
                Environment.Exit(EXIT_RUNTIME_ERROR);
            }
        }
    }
}