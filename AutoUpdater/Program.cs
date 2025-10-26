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
        private const string EVENT_SOURCE = "BridgeExec";
        private const string EVENT_LOG = "Application";

        static int Main(string[] args)
        {
            if (args.Length > 0 && args[0] == "--client")
            {
                // ===== ユーザーセッション側で実行する処理 =====
                _exitCode = UserEntryPoint(args.Skip(1).ToArray());
                return _exitCode;
            }

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

            try
            {
                using (WindowsIdentity id = WindowsIdentity.GetCurrent())
                {
                    WindowsPrincipal principal = new WindowsPrincipal(id);
                    bool isSystem = (id.User != null && id.User.IsWellKnown(WellKnownSidType.LocalSystemSid));
                    bool isAdmin = principal.IsInRole(WindowsBuiltInRole.Administrator);
                    if (!(isSystem || isAdmin))
                    {
                        LogError("Access denied: 実行ユーザー=" + id.Name);
                        _exitCode = EXIT_ACCESS_DENIED;
                        return _exitCode;
                    }
                }

                // ===== サービス側（SYSTEM/管理者）で動く処理 =====
                try
                {
                    // 必要に応じて引数を組み立て
                    string currentExe = Process.GetCurrentProcess().MainModule.FileName;
                    string clientArgs = "--client \"hello\" 42";

                    // 自分自身をユーザーのアクティブセッションで起動
                    _exitCode = ProcessLauncher.RunForActiveUserAndWait(
                        $"\"{currentExe}\" {clientArgs}", 
                        Path.GetDirectoryName(currentExe),
                        TimeSpan.FromMinutes(15));

                    if (_exitCode == EXIT_SUCCESS)
                    {
                        Log("ユーザー側処理 成功");
                    }
                    else
                    {
                        SafeLogEvent($"ユーザー側処理 失敗: ExitCode={_exitCode}", EventLogEntryType.Error);
                    }

                    return _exitCode;
                }
                catch (Exception ex)
                {
                    SafeLogEvent("RunForActiveUser 実行エラー: " + ex, EventLogEntryType.Error);
                    _exitCode = EXIT_RUNTIME_ERROR;
                    return _exitCode;
                }
            }
            catch (Exception ex)
            {
                SafeLogEvent("実行エラー: " + ex, EventLogEntryType.Error);
                _exitCode = EXIT_RUNTIME_ERROR;
                return _exitCode;
            }
        }

        /// <summary>
        /// ユーザーセッション側の呼びたいメソッド
        /// </summary>
        /// <param name="args"></param>
        /// <returns></returns>
        static int UserEntryPoint(string[] args)
        {
            Timer watchdog = new Timer(_ =>
            {
                try { LogError("Watchdog timeout (10min). 強制終了"); } catch { }
                try { Environment.FailFast("Watchdog timeout"); } catch { Process.GetCurrentProcess().Kill(); }
            }, null, TimeSpan.FromMinutes(10), Timeout.InfiniteTimeSpan);

            Mutex mutex = null;
            bool hasLock = false;

            try
            {
                string configPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "AutoUpdater.config");
                if (!File.Exists(configPath))
                {
                    LogError("設定ファイルが見つかりません: " + configPath);
                    _exitCode = EXIT_FILE_NOT_FOUND;
                    return _exitCode;
                }

                ExeConfigurationFileMap fileMap = new ExeConfigurationFileMap();
                fileMap.ExeConfigFilename = configPath;
                Configuration config;
                try
                {
                    config = ConfigurationManager.OpenMappedExeConfiguration(fileMap, ConfigurationUserLevel.None);
                }
                catch (ConfigurationErrorsException cex)
                {
                    LogError("設定ファイル読み込みエラー: " + cex.Message);
                    _exitCode = EXIT_CONFIG_ERROR;
                    return _exitCode;
                }

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
                    return _exitCode;
                }

                string mutexName = MakeGlobalMutexName(targetDir);
                mutex = CreateGlobalMutex(mutexName);

                if (mutex == null)
                {
                    LogError("ミューテックス作成に失敗: " + mutexName);
                    _exitCode = EXIT_RUNTIME_ERROR;
                    return _exitCode;
                }

                if (!mutex.WaitOne(TimeSpan.Zero))
                {
                    LogError("別のインスタンスが実行中のため中断します。");
                    _exitCode = EXIT_SERVICE_UNAVAILABLE;
                    return _exitCode;
                }
                hasLock = true;

                // 何らかの処理

                _exitCode = EXIT_SUCCESS;
                return _exitCode;
            }
            catch (Exception ex)
            {
                LogError("実行エラー: " + ex.ToString());
                _exitCode = EXIT_RUNTIME_ERROR;
                return _exitCode;
            }
            finally
            {
                if (hasLock && mutex != null)
                {
                    try { mutex.ReleaseMutex(); } catch { }
                }
                if (mutex != null) mutex.Dispose();
                if (watchdog != null) watchdog.Dispose();
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
            using (SHA1 sha = SHA1.Create())
            {
                string hash = BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(full))).Replace("-", "");
                return "Global\\ZipReplace48_" + hash.Substring(0, 24);
            }
        }

        static Mutex CreateGlobalMutex(string name)
        {
            try
            {
                var sid = new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null);
                var rule = new MutexAccessRule(sid, MutexRights.FullControl, AccessControlType.Allow);
                var sec = new MutexSecurity();
                sec.AddAccessRule(rule);

                bool createdNew;
                return new Mutex(false, name, out createdNew, sec);
            }
            catch 
            { 
                return null; 
            }
        }
    }
}