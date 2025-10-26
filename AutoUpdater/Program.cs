using System;
using System.Configuration;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Text;
using UserBridge.Core;

namespace AutoUpdater
{
    internal class Program
    {
        // プログラム終了コード一覧
        private const int EXIT_SUCCESS = 0;  // 正常終了
        private const int EXIT_ACCESS_DENIED = 1;  // 権限エラー
        private const int EXIT_RUNTIME_ERROR = 2;  // 実行時エラー

        // 一般的なエラー
        private const int EXIT_INVALID_ARGUMENT = 3;  // 引数不正
        private const int EXIT_FILE_NOT_FOUND = 4;  // ファイルが見つからない
        private const int EXIT_IO_ERROR = 5;  // 入出力エラー
        private const int EXIT_TIMEOUT = 6;  // タイムアウト
        private const int EXIT_NETWORK_ERROR = 7;  // ネットワークエラー
        private const int EXIT_DATABASE_ERROR = 8;  // データベースエラー
        private const int EXIT_CONFIG_ERROR = 9;  // 設定ファイル不正

        // システム系
        private const int EXIT_OUT_OF_MEMORY = 10; // メモリ不足
        private const int EXIT_UNHANDLED_EXCEPTION = 11; // 予期せぬ例外
        private const int EXIT_DEPENDENCY_MISSING = 12; // 依存関係不足
        private const int EXIT_VERSION_MISMATCH = 13; // バージョン不一致

        // アプリケーション固有
        private const int EXIT_USER_CANCELLED = 20; // ユーザー操作による中断
        private const int EXIT_VALIDATION_FAILED = 21; // 入力検証エラー
        private const int EXIT_SERVICE_UNAVAILABLE = 22; // サービス利用不可

        private static int _exitCode = EXIT_UNHANDLED_EXCEPTION;
        private static readonly TimeSpan WATCHDOG_TIMEOUT = TimeSpan.FromMinutes(15);
        private const string EVENT_SOURCE = "BridgeExec";
        private const string EVENT_LOG = "Application";

        static void Main()
        {
            ManualResetEvent watchdogStop = new ManualResetEvent(false);
            Timer watchdog = new Timer(delegate (object _) {
                try { SafeLogEvent(string.Format("Watchdog timeout ({0}). 強制終了します。", WATCHDOG_TIMEOUT), EventLogEntryType.Error); } catch { }
                try { Process.GetCurrentProcess().Kill(); } catch { Environment.FailFast("Watchdog timeout (Kill failed)"); }
            }, null, WATCHDOG_TIMEOUT, Timeout.InfiniteTimeSpan);

            AppDomain.CurrentDomain.UnhandledException += delegate (object s, UnhandledExceptionEventArgs e)
            {
                try { SafeLogEvent("未処理例外: " + e.ExceptionObject, EventLogEntryType.Error); } catch { }
                _exitCode = EXIT_RUNTIME_ERROR;
            };

            TaskScheduler.UnobservedTaskException += delegate (object s, UnobservedTaskExceptionEventArgs e)
            {
                e.SetObserved();
                try { SafeLogEvent("未監視タスク例外: " + e.Exception, EventLogEntryType.Error); } catch { }
                _exitCode = EXIT_RUNTIME_ERROR;
            };

            Mutex mutex = null;
            bool hasLock = false;

            try
            {
                string configPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "AutoUpdater.config");
                if (!File.Exists(configPath))
                {
                    LogError("設定ファイルが見つかりません: " + configPath);
                    _exitCode = EXIT_FILE_NOT_FOUND;
                    return;
                }

                ExeConfigurationFileMap fileMap = new ExeConfigurationFileMap();
                fileMap.ExeConfigFilename = configPath;
                Configuration config = ConfigurationManager.OpenMappedExeConfiguration(fileMap, ConfigurationUserLevel.None);

                string sourceZip = config.AppSettings.Settings["SourceZip"] != null ? config.AppSettings.Settings["SourceZip"].Value : null;
                string targetDir = config.AppSettings.Settings["TargetDir"] != null ? config.AppSettings.Settings["TargetDir"].Value : null;
                string exeNamesRaw = config.AppSettings.Settings["ExeNames"] != null ? config.AppSettings.Settings["ExeNames"].Value : null;

                string[] exeNames = (exeNamesRaw ?? "").Split(',').Select(x => x.Trim()).Where(x => x != "").ToArray();

                System.Collections.Generic.List<string> missing = new System.Collections.Generic.List<string>();
                if (string.IsNullOrWhiteSpace(sourceZip)) missing.Add("SourceZip");
                if (string.IsNullOrWhiteSpace(targetDir)) missing.Add("TargetDir");
                if (exeNames.Length == 0) missing.Add("ExeNames");
                if (missing.Count > 0)
                {
                    LogError("設定値が不足: " + string.Join(", ", missing.ToArray()));
                    _exitCode = EXIT_CONFIG_ERROR;
                    return;
                }

                string mutexName = MakeGlobalMutexName(targetDir);
                mutex = CreateGlobalMutex(mutexName);

                if (mutex == null)
                {
                    SafeLogEvent("ミューテックス作成に失敗: " + mutexName, EventLogEntryType.Error);
                    _exitCode = EXIT_RUNTIME_ERROR;
                    return;
                }

                if (!mutex.WaitOne(TimeSpan.FromSeconds(2)))
                {
                    LogError("別のインスタンスが実行中のため中断します。");
                    _exitCode = EXIT_SERVICE_UNAVAILABLE;
                    return;
                }
                hasLock = true;

                using (WindowsIdentity id = WindowsIdentity.GetCurrent())
                {
                    WindowsPrincipal principal = new WindowsPrincipal(id);
                    bool isSystem = (id.User != null && id.User.IsWellKnown(WellKnownSidType.LocalSystemSid));
                    bool isAdmin = principal.IsInRole(WindowsBuiltInRole.Administrator);
                    if (!(isSystem || isAdmin))
                    {
                        LogError("Access denied: 実行ユーザー=" + id.Name);
                        _exitCode = EXIT_ACCESS_DENIED;
                        return;
                    }
                }

                string cscript = ResolveCscriptPath();
                string script = "C:\\Scripts\\myscript.vbs";

                if (!File.Exists(cscript) || !File.Exists(script))
                {
                    LogError("実行ファイルが見つかりません: cscript=" + cscript + ", script=" + script);
                    _exitCode = EXIT_FILE_NOT_FOUND;
                    return;
                }

                string workDir = Path.GetDirectoryName(script) ?? AppDomain.CurrentDomain.BaseDirectory;
                string cmdLine = string.Format("\"{0}\" //nologo //B \"{1}\"", cscript, script);

                try
                {
                    ProcessLauncher.RunForActiveUser(cmdLine, workDir);
                }
                catch (Exception ex)
                {
                    SafeLogEvent("RunForActiveUser 実行エラー: " + ex, EventLogEntryType.Error);
                    _exitCode = EXIT_RUNTIME_ERROR;
                    return;
                }

                Log("起動要求OK");
                _exitCode = EXIT_SUCCESS;
            }
            catch (OutOfMemoryException oom)
            {
                SafeLogEvent("メモリ不足: " + oom, EventLogEntryType.Error);
                _exitCode = EXIT_OUT_OF_MEMORY;
            }
            catch (IOException ioex)
            {
                SafeLogEvent("入出力エラー: " + ioex, EventLogEntryType.Error);
                _exitCode = EXIT_IO_ERROR;
            }
            catch (Exception ex)
            {
                SafeLogEvent("実行エラー: " + ex, EventLogEntryType.Error);
                _exitCode = EXIT_RUNTIME_ERROR;
            }
            finally
            {
                try { watchdog.Change(Timeout.Infinite, Timeout.Infinite); watchdogStop.Set(); } catch { }
                if (hasLock && mutex != null)
                {
                    try { mutex.ReleaseMutex(); } catch { }
                }
                if (mutex != null) mutex.Dispose();
                if (watchdog != null) watchdog.Dispose();
                if (watchdogStop != null) watchdogStop.Dispose();

                Environment.Exit(_exitCode);
            }
        }

        static bool TryInitEventLog()
        {
            try
            {
                if (!EventLog.SourceExists(EVENT_SOURCE))
                    EventLog.CreateEventSource(EVENT_SOURCE, EVENT_LOG);
                return true;
            }
            catch { return false; }
        }

        static void SafeLogEvent(string message, EventLogEntryType type)
        {
            if (TryInitEventLog())
            {
                try { EventLog.WriteEntry(EVENT_SOURCE, message, type); } catch { }
            }
            try
            {
                string path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "bridgeexec.log");
                File.AppendAllText(path, string.Format("[{0:O} UTC] {1}: {2}{3}", DateTime.UtcNow, type, message, Environment.NewLine));
            }
            catch { }
        }

        static void Log(string message)
        {
            Console.WriteLine("[{0:O} UTC] {1}", DateTime.UtcNow, message);
        }

        static void LogError(string message)
        {
            Console.Error.WriteLine("[{0:O} UTC] {1}", DateTime.UtcNow, message);
        }

        static string MakeGlobalMutexName(string targetDir)
        {
            string full = Path.GetFullPath(targetDir).ToUpperInvariant();
            SHA1 sha = SHA1.Create();
            string hash = BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(full))).Replace("-", "");
            return "Global\\ZipReplace48_" + hash.Substring(0, 24);
        }

        static Mutex CreateGlobalMutex(string name)
        {
            try
            {
                SecurityIdentifier sid = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
                MutexAccessRule rule = new MutexAccessRule(sid, MutexRights.FullControl, AccessControlType.Allow);
                MutexSecurity security = new MutexSecurity();
                security.AddAccessRule(rule);
                bool created;
                Mutex m = new Mutex(false, name, out created);
                m.SetAccessControl(security);
                return m;
            }
            catch
            {
                return null;
            }
        }

        static string ResolveCscriptPath()
        {
            string windir = Environment.GetEnvironmentVariable("WINDIR") ?? "C:\\Windows";
            bool isOS64 = Environment.Is64BitOperatingSystem;
            bool isProc64 = Environment.Is64BitProcess;
            if (isOS64 && !isProc64)
            {
                string sysnative = Path.Combine(windir, "Sysnative", "cscript.exe");
                if (File.Exists(sysnative)) return sysnative;
            }
            string system32 = Path.Combine(windir, "System32", "cscript.exe");
            return system32;
        }
    }
}