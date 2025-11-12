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
using System.Runtime.InteropServices;
using UserBridge.Core;

namespace AutoUpdater
{
    internal class Program
    {
        // ===== プログラム終了コード =====
        private const int EXIT_SUCCESS = 0;                 // 正常終了
        private const int EXIT_ACCESS_DENIED = 1;           // 権限エラー
        private const int EXIT_RUNTIME_ERROR = 2;           // 実行時エラー
        private const int EXIT_INVALID_ARGUMENT = 3;        // 引数不正
        private const int EXIT_FILE_NOT_FOUND = 4;          // ファイルが見つからない
        private const int EXIT_IO_ERROR = 5;                // 入出力エラー
        private const int EXIT_TIMEOUT = 6;                 // タイムアウト
        private const int EXIT_NETWORK_ERROR = 7;           // ネットワークエラー
        private const int EXIT_DATABASE_ERROR = 8;          // データベースエラー
        private const int EXIT_CONFIG_ERROR = 9;            // 設定ファイル不正
        private const int EXIT_OUT_OF_MEMORY = 10;          // メモリ不足
        private const int EXIT_UNHANDLED_EXCEPTION = 11;    // 予期せぬ例外
        private const int EXIT_DEPENDENCY_MISSING = 12;     // 依存関係不足
        private const int EXIT_VERSION_MISMATCH = 13;       // バージョン不一致
        private const int EXIT_USER_CANCELLED = 20;         // ユーザー中断
        private const int EXIT_VALIDATION_FAILED = 21;      // 入力検証エラー
        private const int EXIT_SERVICE_UNAVAILABLE = 22;    // サービス利用不可

        private static int _exitCode = EXIT_UNHANDLED_EXCEPTION;

        private const string EVENT_SOURCE = "AutoUpdater";
        private const string EVENT_LOG = "Application";

        // 既定 3分（設定で上書き可）
        private static TimeSpan WATCHDOG_TIMEOUT = TimeSpan.FromMinutes(3);
        private static CancellationTokenSource _watchdogCts;

        // 起動ごとのワンタイムトークンを Mutex で検証
        private static string _launchToken; // サービス側が生成
        private static string TokenMutexName(string token) => @"Global\AutoUpdater.Token." + token;

        // MoveFileEx (再起動時削除) オプション
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, int dwFlags);
        private const int MOVEFILE_DELAY_UNTIL_REBOOT = 0x4;

        // ========== エントリポイント ==========
        static int Main(string[] args)
        {
            AppDomain.CurrentDomain.UnhandledException += (s, e) =>
            {
                try { SafeLogEvent("未処理例外: " + e.ExceptionObject, EventLogEntryType.Error); } catch { }
                _exitCode = EXIT_RUNTIME_ERROR;
            };

            TaskScheduler.UnobservedTaskException += (s, e) =>
            {
                e.SetObserved();
                try { SafeLogEvent("未監視タスク例外: " + e.Exception, EventLogEntryType.Error); } catch { }
                _exitCode = EXIT_RUNTIME_ERROR;
            };

            try
            {
                if (args.Length > 0 && string.Equals(args[0], "--client", StringComparison.OrdinalIgnoreCase))
                {
                    return UserEntryPoint(args.Skip(1).ToArray());
                }

                // ===== サービス側（SYSTEM/管理者） =====
                if (!EnsureElevatedOrSystem())
                {
                    LogError("Access denied: 管理者または LocalSystem で実行してください。");
                    return _exitCode = EXIT_ACCESS_DENIED;
                }

                var currentExe = Process.GetCurrentProcess().MainModule!.FileName!;
                _launchToken = CreateOneTimeToken();

                // トークン検証用 Mutex を作成（ACL制限）
                using var tokenGate = CreateGlobalMutex(TokenMutexName(_launchToken));
                if (tokenGate == null)
                {
                    SafeLogEvent("トークン用 Mutex の作成に失敗", EventLogEntryType.Error);
                    return _exitCode = EXIT_RUNTIME_ERROR;
                }

                var clientArgs = $"--client {_launchToken}";
                var commandLine = $"\"{currentExe}\" {clientArgs}";

                _exitCode = ProcessLauncher.RunForActiveUserAndWait(
                    commandLine,
                    Path.GetDirectoryName(currentExe)!,
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
                SafeLogEvent("実行エラー: " + ex, EventLogEntryType.Error);
                return _exitCode = EXIT_RUNTIME_ERROR;
            }
        }

        // ========== ユーザーセッション側 ==========
        static int UserEntryPoint(string[] args)
        {
            try
            {
                if (args.Length < 1)
                {
                    LogError("不正な起動。トークン未指定。");
                    return EXIT_ACCESS_DENIED;
                }
                var token = args[0];

                // サービス側が作ったトークン Mutex が存在するかで検証
                if (!ValidateTokenWithMutex(token))
                {
                    LogError("不正な起動。認証トークンが一致しません。");
                    return EXIT_ACCESS_DENIED;
                }

                // 設定ファイル
                var configPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "AutoUpdater.config");
                if (!File.Exists(configPath))
                {
                    LogError("設定ファイルが見つかりません: " + configPath);
                    return EXIT_FILE_NOT_FOUND;
                }

                var fileMap = new ExeConfigurationFileMap { ExeConfigFilename = configPath };
                Configuration config;
                try
                {
                    config = ConfigurationManager.OpenMappedExeConfiguration(fileMap, ConfigurationUserLevel.None);
                }
                catch (ConfigurationErrorsException cex)
                {
                    LogError("設定ファイル読み込みエラー: " + cex.Message);
                    return EXIT_CONFIG_ERROR;
                }

                // ウォッチドッグ（既定3分、設定 WatchdogSeconds=10〜600 なら上書き）
                WATCHDOG_TIMEOUT = LoadWatchdogTimeoutFromConfig(config);
                StartWatchdog(WATCHDOG_TIMEOUT);

                // 設定読み込み（堅牢化）
                var sourceZip = GetRequiredSetting(config, "SourceZip");
                var targetDir = GetRequiredSetting(config, "TargetDir");
                var exeNamesRaw = GetRequiredSetting(config, "ExeNames");

                if (sourceZip == null || targetDir == null || exeNamesRaw == null)
                {
                    LogError("設定値が不足: SourceZip/TargetDir/ExeNames は必須です。");
                    return EXIT_CONFIG_ERROR;
                }

                sourceZip = sourceZip.Trim();
                targetDir = targetDir.Trim();

                // セパレータ/空白/セミコロン対応
                var exeNames = exeNamesRaw
                    .Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries)
                    .Select(x => x.Trim())
                    .Where(x => x.Length > 0)
                    .ToArray();

                if (exeNames.Length == 0)
                {
                    LogError("ExeNames が空です。");
                    return EXIT_CONFIG_ERROR;
                }

                // 絶対パス確認
                if (!Path.IsPathRooted(sourceZip) || !Path.IsPathRooted(targetDir))
                {
                    LogError("SourceZip/TargetDir は絶対パスで指定してください。");
                    return EXIT_CONFIG_ERROR;
                }

                // 誤設定防止: sourceZip が targetDir 配下は不可
                if (IsSubPathOf(Path.GetDirectoryName(sourceZip)!, targetDir))
                {
                    LogError("誤設定: SourceZip が TargetDir 配下です。自己削除の恐れがあるため禁止。");
                    return EXIT_CONFIG_ERROR;
                }

                // 存在チェック
                if (!Directory.Exists(targetDir))
                {
                    LogError("対象フォルダが存在しません: " + targetDir);
                    return EXIT_FILE_NOT_FOUND;
                }
                if (!File.Exists(sourceZip))
                {
                    LogError("元ZIP が見つかりません: " + sourceZip);
                    return EXIT_FILE_NOT_FOUND;
                }

                var exePaths = exeNames.Select(n => Path.Combine(targetDir, n)).ToArray();
                var targetZip = Path.Combine(targetDir, Path.GetFileName(sourceZip));

                // 稼働中（ロック）判定
                if (IsAnyTargetLocked(exePaths))
                {
                    LogError("対象実行ファイルがロック中のため中断します。");
                    return EXIT_RUNTIME_ERROR;
                }

                // 新旧比較
                var srcZipTimeUtc = File.GetLastWriteTimeUtc(sourceZip);
                bool dirEmpty = IsDirectoryEmpty(targetDir);
                bool hasTargetZip = File.Exists(targetZip);
                DateTime? targetZipTimeUtc = hasTargetZip ? File.GetLastWriteTimeUtc(targetZip) : (DateTime?)null;
                var dirLatestUtc = GetDirectoryLatestWriteTimeUtc(targetDir);
                var baselineUtc = MaxUtc(targetZipTimeUtc ?? DateTime.MinValue, dirLatestUtc ?? DateTime.MinValue);

                Log($"元ZIP(UTC): {srcZipTimeUtc:O}");
                Log($"対象側基準(UTC): {baselineUtc:O}");
                Log($"対象フォルダは空?: {dirEmpty}, 対象側ZIPあり?: {hasTargetZip}");

                bool shouldReplace = dirEmpty || !hasTargetZip || srcZipTimeUtc > baselineUtc;
                if (!shouldReplace)
                {
                    Log("更新の必要がないため差し替えは行いません。");
                    return EXIT_SUCCESS;
                }

                // クリティカル直前の再ロックチェック
                if (IsAnyTargetLocked(exePaths))
                {
                    LogError("チェック後に実行ファイルがロックされたため中断します。");
                    return EXIT_RUNTIME_ERROR;
                }

                // 差し替え実行（ステージング→アトミックスワップ）
                int rc = ReplaceFolderWithZipSafe(sourceZip, targetDir, Path.GetFileName(sourceZip), exePaths)
                    ? EXIT_SUCCESS
                    : EXIT_RUNTIME_ERROR;

                return rc;
            }
            catch (OperationCanceledException)
            {
                LogError($"Watchdog timeout ({WATCHDOG_TIMEOUT}). 中断します。");
                return EXIT_TIMEOUT;
            }
            catch (Exception ex)
            {
                LogError("実行エラー: " + ex);
                return EXIT_RUNTIME_ERROR;
            }
            finally
            {
                _watchdogCts?.Dispose();
            }
        }

        // ===== 共通ユーティリティ =====

        static bool EnsureElevatedOrSystem()
        {
            try
            {
                using var id = WindowsIdentity.GetCurrent();
                var principal = new WindowsPrincipal(id);
                bool isSystem = (id.User != null && id.User.IsWellKnown(WellKnownSidType.LocalSystemSid));
                bool isAdmin = principal.IsInRole(WindowsBuiltInRole.Administrator);
                return isSystem || isAdmin;
            }
            catch { return false; }
        }

        static void StartWatchdog(TimeSpan timeout)
        {
            _watchdogCts = new CancellationTokenSource(timeout);
        }
        static void CheckCancel() => _watchdogCts?.Token.ThrowIfCancellationRequested();

        static TimeSpan LoadWatchdogTimeoutFromConfig(Configuration config)
        {
            var v = config.AppSettings.Settings["WatchdogSeconds"]?.Value;
            if (int.TryParse(v, out var sec) && sec >= 10 && sec <= 600) // 10〜600秒に制限
                return TimeSpan.FromSeconds(sec);
            return TimeSpan.FromMinutes(3);
        }

        static string CreateOneTimeToken()
        {
            Span<byte> buf = stackalloc byte[32];
            RandomNumberGenerator.Fill(buf);
            return Convert.ToBase64String(buf);
        }

        static bool ValidateTokenWithMutex(string token)
        {
            try
            {
                using var m = Mutex.OpenExisting(TokenMutexName(token));
                return true;
            }
            catch
            {
                return false;
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
            var wroteEvent = false;
            try
            {
                if (TryInitEventLog())
                {
                    EventLog.WriteEntry(EVENT_SOURCE, message, type);
                    wroteEvent = true;
                }
            }
            catch { /* ignore */ }

            try
            {
                string path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "autoupdater.log");
                File.AppendAllText(path, $"[{DateTime.UtcNow:O} UTC] {type}: {message}{Environment.NewLine}");
            }
            catch { if (!wroteEvent) { /* どうにもならない */ } }
        }

        static void Log(string message) =>
            Console.WriteLine("[{0:O} UTC] {1}", DateTime.UtcNow, message);
        static void LogError(string message) =>
            Console.Error.WriteLine("[{0:O} UTC] {1}", DateTime.UtcNow, message);

        static string GetRequiredSetting(Configuration cfg, string key) =>
            cfg.AppSettings.Settings[key]?.Value;

        static bool IsDirectoryEmpty(string path)
        {
            try { return !Directory.EnumerateFileSystemEntries(path).Any(); }
            catch { return false; }
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
                    CheckCancel();
                    DateTime t;
                    try { t = File.GetLastWriteTimeUtc(f); }
                    catch { continue; }
                    if (t > latest) latest = t;
                    any = true;
                }
                return any ? latest : (DateTime?)null;
            }
            catch { return null; }
        }
        static DateTime MaxUtc(DateTime a, DateTime b) => a >= b ? a : b;

        static bool IsAnyTargetLocked(string[] paths)
        {
            foreach (var p in paths)
            {
                CheckCancel();
                try
                {
                    using var fs = new FileStream(p, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
                }
                catch (FileNotFoundException)
                {
                    continue; // まだ存在しないのはOK
                }
                catch (IOException)
                {
                    return true; // ロック中
                }
                catch
                {
                    return true; // 権限等も保守的にロック扱い
                }
            }
            return false;
        }

        static bool IsSubPathOf(string child, string parent)
        {
            try
            {
                var a = Path.GetFullPath(child).TrimEnd(Path.DirectorySeparatorChar).ToUpperInvariant();
                var b = Path.GetFullPath(parent).TrimEnd(Path.DirectorySeparatorChar).ToUpperInvariant();
                return a.StartsWith(b + Path.DirectorySeparatorChar);
            }
            catch { return false; }
        }

        // ===== 置換処理（ステージング＋アトミックスワップ） =====

        static bool ReplaceFolderWithZipSafe(string sourceZip, string targetDir, string zipFileName, string[] exePaths)
        {
            var tempBase = Path.Combine(Path.GetTempPath(), "ZipReplace_" + Guid.NewGuid().ToString("N"));
            var tempExtract = Path.Combine(tempBase, "extract");
            var tempStage = Path.Combine(tempBase, "stage");

            Directory.CreateDirectory(tempExtract);
            Directory.CreateDirectory(tempStage);

            try
            {
                // Zip Slip + Zip Bomb 対策付き展開
                SafeExtractZip(sourceZip, tempExtract,
                    maxTotalBytes: 2L * 1024 * 1024 * 1024,     // 2GB
                    maxEntryBytes: 512L * 1024 * 1024);         // 512MB/entry

                // ステージングに ZIP も配置（従来仕様）
                Retry(() => File.Copy(sourceZip, Path.Combine(tempStage, zipFileName), overwrite: true));

                // 展開物をステージングへコピー
                CopyAll(new DirectoryInfo(tempExtract), new DirectoryInfo(tempStage));

                // 直前ロック再チェック
                if (IsAnyTargetLocked(exePaths))
                {
                    Log("コピー直前にロックが検知されたため中断しました。");
                    return false;
                }

                // アトミックに入れ替え（失敗時はロールバック）
                if (!AtomicSwap(targetDir, tempStage))
                {
                    LogError("アトミックスワップに失敗しました。");
                    return false;
                }
                return true;
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                LogError("差し替え処理中にエラー: " + ex);
                return false;
            }
            finally
            {
                // 時間をかけないよう非同期削除（少し待つとロック解除されやすい）
                Task.Run(() =>
                {
                    Thread.Sleep(2000);
                    try { TryDeleteDirectory(tempBase); }
                    catch
                    {
                        // 最後の手段: 再起動後削除を予約
                        try { MoveFileEx(tempBase, null, MOVEFILE_DELAY_UNTIL_REBOOT); } catch { }
                    }
                });
            }
        }

        static void SafeExtractZip(string zipPath, string extractDir, long maxTotalBytes, long maxEntryBytes)
        {
            var basePath = Path.GetFullPath(extractDir);
            if (!basePath.EndsWith(Path.DirectorySeparatorChar.ToString()))
                basePath += Path.DirectorySeparatorChar;

            long total = 0;
            using (var zip = ZipFile.OpenRead(zipPath))
            {
                foreach (var entry in zip.Entries)
                {
                    CheckCancel();

                    // ZIPは'/'区切り
                    var entryName = entry.FullName.Replace('/', Path.DirectorySeparatorChar);
                    if (string.IsNullOrEmpty(entryName))
                        continue;

                    // ディレクトリエントリ？
                    bool isDir = entry.FullName.EndsWith("/", StringComparison.Ordinal);

                    // 絶対パス/ドライブ直指定は禁止
                    if (Path.IsPathRooted(entryName))
                        throw new InvalidDataException("無効なZIPエントリ（絶対パス）: " + entry.FullName);

                    var combined = Path.GetFullPath(Path.Combine(basePath, entryName));

                    // ベース配下に収まっているか
                    if (!combined.StartsWith(basePath, StringComparison.OrdinalIgnoreCase))
                        throw new InvalidDataException("無効なZIPエントリ（パストラバーサル）: " + entry.FullName);

                    if (isDir)
                    {
                        Directory.CreateDirectory(combined);
                        continue;
                    }

                    // Zip Bomb 制限
                    if (entry.Length > maxEntryBytes)
                        throw new InvalidDataException($"ZIPエントリが大きすぎます: {entry.FullName} ({entry.Length} bytes)");
                    total += entry.Length;
                    if (total > maxTotalBytes)
                        throw new InvalidDataException("ZIPの展開サイズ上限を超過しました");

                    var dirName = Path.GetDirectoryName(combined);
                    if (!string.IsNullOrEmpty(dirName)) Directory.CreateDirectory(dirName);

                    Retry(() => entry.ExtractToFile(combined, overwrite: true));
                }
            }
        }

        static bool AtomicSwap(string targetDir, string stagedDir)
        {
            // stagedDir を targetDir の親配下に移したいので、まず targetDir が存在する前提
            var parent = Path.GetDirectoryName(targetDir.TrimEnd(Path.DirectorySeparatorChar));
            if (string.IsNullOrEmpty(parent)) { LogError("AtomicSwap: 親ディレクトリを解決できません。"); return false; }

            var backup = targetDir.TrimEnd(Path.DirectorySeparatorChar) + ".__old";
            try
            {
                // 既存バックアップがあれば掃除
                if (Directory.Exists(backup)) TryDeleteDirectory(backup);

                // target -> backup（同一ボリュームならメタデータ操作で高速）
                Directory.Move(targetDir, backup);

                // staged -> target（staged は TEMP にあるので、Move 先は parent 直下にする）
                Directory.Move(stagedDir, targetDir);

                // バックアップ削除
                TryDeleteDirectory(backup);
                return true;
            }
            catch (Exception ex)
            {
                LogError("Atomic swap 失敗。ロールバック試行: " + ex);
                try
                {
                    if (Directory.Exists(targetDir)) TryDeleteDirectory(targetDir);
                    if (Directory.Exists(backup)) Directory.Move(backup, targetDir);
                }
                catch (Exception rex)
                {
                    LogError("ロールバック失敗: " + rex);
                }
                return false;
            }
        }

        static void CopyAll(DirectoryInfo source, DirectoryInfo target)
        {
            var srcRoot = source.FullName;
            if (!srcRoot.EndsWith(Path.DirectorySeparatorChar.ToString()))
                srcRoot += Path.DirectorySeparatorChar;

            foreach (var dir in source.EnumerateDirectories("*", SearchOption.AllDirectories))
            {
                CheckCancel();
                var rel = dir.FullName.Substring(srcRoot.Length);
                var destDir = Path.Combine(target.FullName, rel);
                Directory.CreateDirectory(destDir);
            }

            foreach (var file in source.EnumerateFiles("*", SearchOption.AllDirectories))
            {
                CheckCancel();
                var rel = file.FullName.Substring(srcRoot.Length);
                var dest = Path.Combine(target.FullName, rel);
                var parent = Path.GetDirectoryName(dest);
                if (!string.IsNullOrEmpty(parent)) Directory.CreateDirectory(parent);

                Retry(() =>
                {
                    CheckCancel();
                    try { if (File.Exists(dest)) File.SetAttributes(dest, FileAttributes.Normal); } catch { }
                    file.CopyTo(dest, true);
                });
            }
        }

        static void ClearDirectory(string dir)
        {
            foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.TopDirectoryOnly))
            {
                CheckCancel();
                Retry(() =>
                {
                    CheckCancel();
                    try { File.SetAttributes(file, FileAttributes.Normal); } catch { }
                    File.Delete(file);
                });
            }
            foreach (var sub in Directory.EnumerateDirectories(dir, "*", SearchOption.TopDirectoryOnly))
            {
                CheckCancel();
                Retry(() => { CheckCancel(); TryDeleteDirectory(sub); });
            }
        }

        static void Retry(Action action, int attempts = 5, int initialDelayMs = 80)
        {
            var delay = initialDelayMs;
            for (int i = 1; ; i++)
            {
                CheckCancel();
                try
                {
                    action();
                    return;
                }
                catch (Exception) when (i < attempts)
                {
                    Thread.Sleep(delay);
                    delay = Math.Min(delay * 2, 2000);
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
                // 掃除失敗は致命でないので握りつぶす
            }
        }

        static Mutex CreateGlobalMutex(string name)
        {
            try
            {
                var sec = new MutexSecurity();
                var me = WindowsIdentity.GetCurrent().User!;
                sec.AddAccessRule(new MutexAccessRule(me, MutexRights.FullControl, AccessControlType.Allow));
                sec.AddAccessRule(new MutexAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                                                      MutexRights.FullControl, AccessControlType.Allow));
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
