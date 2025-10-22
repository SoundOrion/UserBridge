using System.Diagnostics;
using System.Security.Principal;
using UserBridge.Core;

namespace UserBridge.Net
{
    internal class Program
    {
        static int Main()
        {
            AppDomain.CurrentDomain.UnhandledException += (s, e) => { try { EventLog.WriteEntry("BridgeExec", $"未処理例外: {e.ExceptionObject}", EventLogEntryType.Error); } catch { } Environment.ExitCode = 2; };
            try
            {
                using var id = WindowsIdentity.GetCurrent();
                var isSystem = string.Equals(id.Name, "NT AUTHORITY\\SYSTEM", StringComparison.OrdinalIgnoreCase);
                var isAdmin = new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
                if (!(isSystem || isAdmin)) { Console.Error.WriteLine($"Access denied: 実行ユーザー={id.Name}"); return 1; }


                string cscript = Environment.ExpandEnvironmentVariables(@"%SystemRoot%\\System32\\cscript.exe");
                string script = @"C:\\Scripts\\myscript.vbs";
                ProcessLauncher.RunForActiveUser($"\"{cscript}\" //nologo \"{script}\"", @"C:\\Scripts");
                Console.WriteLine("起動要求OK");
                return 0;
            }
            catch (Exception ex)
            {
                try { EventLog.WriteEntry("BridgeExec", $"実行エラー: {ex}", EventLogEntryType.Error); } catch { }
                return 2;
            }
        }
    }
}