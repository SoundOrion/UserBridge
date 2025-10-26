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
using System.IO.Compression;
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

                try
                {
                    if (!mutex.WaitOne(TimeSpan.Zero))
                    {
                        LogError("別のインスタンスが実行中のため中断します。");
                        _exitCode = EXIT_SERVICE_UNAVAILABLE;
                        return _exitCode;
                    }
                    hasLock = true;
                }
                catch (AbandonedMutexException)
                {
                    // 前回異常終了などでミューテックスが放棄されていた場合
                    LogError("前回の実行が異常終了していました。ロックを引き継いで続行します。");
                    hasLock = true;
                }

                // ここから実際の処理

                // フォルダの存在だけチェック
                if (!Directory.Exists(targetDir))
                {
                    LogError("対象フォルダが存在しないため、処理を行いません。");
                    _exitCode = EXIT_FILE_NOT_FOUND;
                    return _exitCode;
                }

                // 元ZIPは必須（ここは従来どおり）
                if (!File.Exists(sourceZip))
                {
                    LogError("元ZIP が見つからないため、処理を行いません。");
                    _exitCode = EXIT_FILE_NOT_FOUND;
                    return _exitCode;
                }

                var targetZip = Path.Combine(targetDir, Path.GetFileName(sourceZip));
                var exePaths = exeNames.Select(n => Path.Combine(targetDir, n)).ToArray();

                // 任意：プロセス稼働チェック（安全のため維持）
                if (IsAnyProcessRunning(exePaths))
                {
                    LogError("対象の実行ファイルに対応するプロセスが稼働中のため、処理を行いません。");
                    _exitCode = EXIT_RUNTIME_ERROR;
                    return _exitCode;
                }

                // --- 更新要否の判定 ---
                bool dirEmpty = IsDirectoryEmpty(targetDir);
                bool hasTargetZip = File.Exists(targetZip);

                var srcZipTimeUtc = File.GetLastWriteTimeUtc(sourceZip);

                // 対象側の「新しさ」＝(a) 対象側ZIPの時刻, (b) 対象フォルダ配下ファイルの最終更新時刻 の最大
                DateTime? targetZipTimeUtc = hasTargetZip ? File.GetLastWriteTimeUtc(targetZip) : (DateTime?)null;
                var dirLatestUtc = GetDirectoryLatestWriteTimeUtc(targetDir);
                var baselineUtc = MaxUtc(targetZipTimeUtc ?? DateTime.MinValue, dirLatestUtc ?? DateTime.MinValue);

                Log($"元ZIP(UTC): {srcZipTimeUtc:O}");
                Log($"対象側基準(UTC): {baselineUtc:O}");
                Log($"対象フォルダは空?: {dirEmpty}, 対象側ZIPあり?: {hasTargetZip}");

                // ① フォルダが空 → 更新
                // ② 対象側ZIPが無い → 更新
                // ③ 上記以外 → 元ZIPが基準より新しければ更新
                bool shouldReplace = dirEmpty || !hasTargetZip || srcZipTimeUtc > baselineUtc;

                if (!shouldReplace)
                {
                    Log("更新の必要がないため、差し替えは行いません。");
                    _exitCode = EXIT_SUCCESS;
                    return _exitCode;
                }

                // クリティカル区間直前の再チェック
                if (IsAnyProcessRunning(exePaths))
                {
                    LogError("チェック後に対象のプロセスが稼働開始したため、中断します。");
                    _exitCode = EXIT_RUNTIME_ERROR;
                    return _exitCode;
                }

                // --- 差し替え ---
                if (ReplaceFolderWithZipSafe(sourceZip, targetDir, Path.GetFileName(sourceZip), exePaths))
                {
                    _exitCode = EXIT_RUNTIME_ERROR;
                    return _exitCode;
                }

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



        static bool IsDirectoryEmpty(string path)
        {
            try
            {
                return !Directory.EnumerateFileSystemEntries(path).Any();
            }
            catch
            {
                // アクセスできない場合は保守的に「空ではない」とみなす
                return false;
            }
        }

        static DateTime? GetDirectoryLatestWriteTimeUtc(string path)
        {
            try
            {
                var files = Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories);
                DateTime latest = DateTime.MinValue;
                bool any = false;
                foreach (var f in files)
                {
                    DateTime t;
                    try { t = File.GetLastWriteTimeUtc(f); }
                    catch { continue; }
                    if (t > latest) latest = t;
                    any = true;
                }
                return any ? latest : (DateTime?)null;
            }
            catch
            {
                // 取れなければ「なし」
                return null;
            }
        }
        static DateTime MaxUtc(DateTime a, DateTime b) => a >= b ? a : b;
        // exe のフルパスに紐づけて稼働判定（名前衝突を避ける）
        // アクセスできないケースは保守的に「稼働中とみなす」
        static bool IsAnyProcessRunning(string[] fullExePaths)
        {
            var targets = fullExePaths
                .Select(p => new { Name = Path.GetFileNameWithoutExtension(p), Path = NormalizeFullPath(p) })
                .Where(x => !string.IsNullOrWhiteSpace(x.Name))
                .GroupBy(x => x.Name, StringComparer.OrdinalIgnoreCase);

            foreach (var g in targets)
            {
                Process[] procs = Array.Empty<Process>();
                try { procs = Process.GetProcessesByName(g.Key); } catch { }

                foreach (var p in procs)
                {
                    try
                    {
                        var exePath = p.MainModule?.FileName;
                        if (exePath == null) return true; // 情報が取れない場合は保守的にtrue
                        var exeNorm = NormalizeFullPath(exePath);
                        foreach (var t in g)
                            if (PathEquals(exeNorm, t.Path)) return true;
                    }
                    catch
                    {
                        return true; // アクセス失敗時も保守的にtrue
                    }
                    finally
                    {
                        try { p.Dispose(); } catch { }
                    }
                }
            }
            return false;
        }

        static string NormalizeFullPath(string path)
        {
            var full = Path.GetFullPath(path);
            // 末尾セパレータは削る（比較一貫性のため）
            return full.TrimEnd(Path.DirectorySeparatorChar);
        }

        static bool PathEquals(string a, string b) =>
            string.Equals(NormalizeFullPath(a), NormalizeFullPath(b), StringComparison.OrdinalIgnoreCase);

        static bool ReplaceFolderWithZipSafe(string sourceZip, string targetDir, string zipFileName, string[] exePaths)
        {
            // 一時展開先（安全に差し替えるため）
            var tempBase = Path.Combine(Path.GetTempPath(), "ZipReplace_" + Guid.NewGuid().ToString("N"));
            var tempExtract = Path.Combine(tempBase, "extract");
            var tempStage = Path.Combine(tempBase, "stage");

            Directory.CreateDirectory(tempExtract);
            Directory.CreateDirectory(tempStage);

            try
            {
                // 安全に展開（Zip Slip / Zip Bomb 防止）
                SafeExtractZip(sourceZip, tempExtract);

                // ステージングに ZIP 自体も置く（元の仕様どおり）
                Retry(() => File.Copy(sourceZip, Path.Combine(tempStage, zipFileName), overwrite: true));

                // 展開物をステージングへコピー
                CopyAll(new DirectoryInfo(tempExtract), new DirectoryInfo(tempStage));

                // 直前再チェック（稼働開始を検知）
                if (IsAnyProcessRunning(exePaths))
                {
                    Log("コピー直前にプロセスが稼働開始したため中断しました。");
                    return false;
                }

                // 対象フォルダ内をクリア
                ClearDirectory(targetDir);

                // ステージング → 対象へコピー（Move ではなく Copy による上書き）
                CopyAll(new DirectoryInfo(tempStage), new DirectoryInfo(targetDir));
                return true;
            }
            catch (Exception ex)
            {
                LogError("差し替え処理中にエラー: " + ex);
                return false;
            }
            finally
            {
                TryDeleteDirectory(tempBase);
            }
        }

        // Zip Slip / Zip Bomb 防止つき展開
        static void SafeExtractZip(string zipPath, string extractDir)
        {
            var basePath = Path.GetFullPath(extractDir);
            if (!basePath.EndsWith(Path.DirectorySeparatorChar.ToString()))
                basePath += Path.DirectorySeparatorChar; // 末尾セパレータを保証

            using (var zip = ZipFile.OpenRead(zipPath))
            {
                foreach (var entry in zip.Entries)
                {
                    // ZIPは'/'区切りなので正規化
                    var entryName = entry.FullName.Replace('/', Path.DirectorySeparatorChar);

                    // 空エントリはスキップ
                    if (string.IsNullOrEmpty(entryName))
                        continue;

                    // 絶対パス／ドライブ直指定は禁止
                    if (Path.IsPathRooted(entryName))
                        throw new InvalidDataException("無効なZIPエントリ（絶対パス）: " + entry.FullName);

                    var combined = Path.GetFullPath(Path.Combine(basePath, entryName));

                    // ベース配下に収まっているか（末尾セパレータ保護付き）
                    if (!combined.StartsWith(basePath, StringComparison.OrdinalIgnoreCase))
                        throw new InvalidDataException("無効なZIPエントリ（パストラバーサルの可能性）: " + entry.FullName);

                    // ディレクトリエントリ？
                    if (entry.FullName.EndsWith("/", StringComparison.Ordinal))
                    {
                        Directory.CreateDirectory(combined);
                        continue;
                    }

                    var dirName = Path.GetDirectoryName(combined);
                    if (!string.IsNullOrEmpty(dirName))
                    {
                        Directory.CreateDirectory(dirName);
                    }
                    Retry(() => entry.ExtractToFile(combined, overwrite: true));
                }
            }
        }

        static void ClearDirectory(string dir)
        {
            // ファイル削除
            foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.TopDirectoryOnly))
            {
                Retry(() =>
                {
                    try { File.SetAttributes(file, FileAttributes.Normal); } catch { }
                    File.Delete(file);
                });
            }
            // サブフォルダ削除
            foreach (var sub in Directory.EnumerateDirectories(dir, "*", SearchOption.TopDirectoryOnly))
            {
                Retry(() => TryDeleteDirectory(sub));
            }
        }

        static void CopyAll(DirectoryInfo source, DirectoryInfo target)
        {
            // ソースのルート末尾に必ずセパレータを付与し、相対パスの計算を安定化
            var srcRoot = source.FullName;
            if (!srcRoot.EndsWith(Path.DirectorySeparatorChar.ToString()))
                srcRoot += Path.DirectorySeparatorChar;

            // 先にディレクトリを作成
            foreach (var dir in source.EnumerateDirectories("*", SearchOption.AllDirectories))
            {
                var rel = dir.FullName.Substring(srcRoot.Length);
                var destDir = Path.Combine(target.FullName, rel);
                Directory.CreateDirectory(destDir);
            }
            // ファイルをコピー
            foreach (var file in source.EnumerateFiles("*", SearchOption.AllDirectories))
            {
                var rel = file.FullName.Substring(srcRoot.Length);
                var dest = Path.Combine(target.FullName, rel);
                var parent = Path.GetDirectoryName(dest);
                if (!string.IsNullOrEmpty(parent))
                    Directory.CreateDirectory(parent);
                Retry(() =>
                {
                    try { if (File.Exists(dest)) File.SetAttributes(dest, FileAttributes.Normal); } catch { }
                    file.CopyTo(dest, true);
                });
            }
        }

        // 小さなバックオフ付きリトライ（共有違反などの軽微な失敗向け）
        static void Retry(Action action, int attempts = 5, int initialDelayMs = 80)
        {
            var delay = initialDelayMs;
            for (int i = 1; ; i++)
            {
                try
                {
                    action();
                    return;
                }
                catch (Exception) when (i < attempts)
                {
                    Thread.Sleep(delay);
                    delay *= 2;
                }
            }
        }

        static void TryDeleteDirectory(string dir)
        {
            try
            {
                if (Directory.Exists(dir))
                {
                    foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
                    {
                        try { File.SetAttributes(file, FileAttributes.Normal); } catch { }
                    }
                    Directory.Delete(dir, true);
                }
            }
            catch
            {
                // 掃除失敗は致命でないので黙殺
            }
        }
    }
}