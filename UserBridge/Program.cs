using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;

namespace UserBridge
{
    /// <summary>
    /// サービス（SYSTEM/管理者）から、アクティブなログインユーザーのセッション内で任意コマンドを実行するユーティリティ。
    /// 時間制限は設けず、成功/失敗にかかわらず本プロセスは確実に終了する。
    /// </summary>
    internal class Program
    {
        // ====== 終了コード ======
        private const int EXIT_SUCCESS = 0;
        private const int EXIT_ACCESS_DENIED = 1;
        private const int EXIT_RUNTIME_ERROR = 2;

        private static int _exitCode = EXIT_RUNTIME_ERROR;

        // ===== P/Invoke =====

        /// <summary>
        /// 列挙されているセッション情報を取得します（WTS API）。
        /// </summary>
        /// <param name="hServer">WTS サーバーハンドル（通常は IntPtr.Zero）。</param>
        /// <param name="Reserved">予約（0 を指定）。</param>
        /// <param name="Version">バージョン（1 を指定）。</param>
        /// <param name="ppSessionInfo">結果のセッション情報配列へのポインタ（出力）。</param>
        /// <param name="pCount">返されたセッション数（出力）。</param>
        /// <returns>成功したら true。</returns>
        [DllImport("wtsapi32.dll", SetLastError = true)]
        static extern bool WTSEnumerateSessions(IntPtr hServer, int Reserved, int Version,
            out IntPtr ppSessionInfo, out int pCount);

        /// <summary>
        /// WTSEnumerateSessions で割り当てられたメモリを解放します。
        /// </summary>
        /// <param name="pMemory">解放するメモリのポインタ。</param>
        [DllImport("wtsapi32.dll")] static extern void WTSFreeMemory(IntPtr pMemory);

        /// <summary>
        /// 指定セッションのユーザートークンを取得します。
        /// </summary>
        /// <param name="SessionId">セッション ID。</param>
        /// <param name="phToken">取得したトークンハンドル（出力）。</param>
        /// <returns>成功したら true。</returns>
        [DllImport("wtsapi32.dll", SetLastError = true)]
        static extern bool WTSQueryUserToken(uint SessionId, out IntPtr phToken);

        /// <summary>
        /// トークンを複製して新しいトークンを作成します（DuplicateTokenEx）。
        /// </summary>
        /// <param name="hExistingToken">既存トークンハンドル。</param>
        /// <param name="dwDesiredAccess">要求するアクセス権。</param>
        /// <param name="lpTokenAttributes">トークン属性（通常は IntPtr.Zero）。</param>
        /// <param name="SecurityImpersonationLevel">セキュリティのインパーソネーション レベル。</param>
        /// <param name="TokenType">トークンタイプ（Primary / Impersonation 等）。</param>
        /// <param name="phNewToken">新しいトークンハンドル（出力）。</param>
        /// <returns>成功したら true。</returns>
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes,
            int SecurityImpersonationLevel, int TokenType, out IntPtr phNewToken);

        /// <summary>
        /// 指定トークン用の環境ブロックを生成します（CreateEnvironmentBlock）。
        /// </summary>
        /// <param name="lpEnvironment">環境ブロックポインタ（出力）。</param>
        /// <param name="hToken">トークンハンドル。</param>
        /// <param name="bInherit">継承フラグ。</param>
        /// <returns>成功したら true。</returns>
        [DllImport("userenv.dll", SetLastError = true)]
        static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

        /// <summary>
        /// CreateEnvironmentBlock で確保した環境ブロックを破棄します。
        /// </summary>
        /// <param name="lpEnvironment">破棄する環境ブロックのポインタ。</param>
        [DllImport("userenv.dll", SetLastError = true)]
        static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

        /// <summary>
        /// 指定したユーザートークンでプロセスを作成します（CreateProcessAsUser）。
        /// </summary>
        /// <param name="hToken">ユーザートークンハンドル（Primary トークン）。</param>
        /// <param name="lpApplicationName">アプリケーション名（null の場合はコマンドラインを解析）。</param>
        /// <param name="lpCommandLine">コマンドライン文字列。</param>
        /// <param name="lpProcessAttributes">プロセス属性（通常 IntPtr.Zero）。</param>
        /// <param name="lpThreadAttributes">スレッド属性（通常 IntPtr.Zero）。</param>
        /// <param name="bInheritHandles">ハンドル継承フラグ。</param>
        /// <param name="dwCreationFlags">作成フラグ（例: CREATE_UNICODE_ENVIRONMENT）。</param>
        /// <param name="lpEnvironment">環境ブロックポインタ（CreateEnvironmentBlock で取得した値）。</param>
        /// <param name="lpCurrentDirectory">カレントディレクトリ。</param>
        /// <param name="lpStartupInfo">STARTUPINFO 構造体（ref）。</param>
        /// <param name="lpProcessInformation">生成されたプロセス情報（出力）。</param>
        /// <returns>成功したら true。</returns>
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool CreateProcessAsUser(IntPtr hToken, string lpApplicationName, string lpCommandLine,
            IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags,
            IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        /// <summary>
        /// 指定プロセスのトークンを開きます（OpenProcessToken）。
        /// </summary>
        /// <param name="ProcessHandle">プロセスハンドル。</param>
        /// <param name="DesiredAccess">要求するアクセス。</param>
        /// <param name="TokenHandle">取得したトークンハンドル（出力）。</param>
        /// <returns>成功したら true。</returns>
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        /// <summary>
        /// トークン特権を調整します（AdjustTokenPrivileges）。
        /// </summary>
        /// <param name="TokenHandle">トークンハンドル。</param>
        /// <param name="DisableAllPrivileges">全特権を無効化するか。</param>
        /// <param name="NewState">新しい特権状態（ref）。</param>
        /// <param name="BufferLength">バッファ長。</param>
        /// <param name="PreviousState">前の状態（通常 IntPtr.Zero）。</param>
        /// <param name="ReturnLength">返却長（出力）。</param>
        /// <returns>成功したら true。</returns>
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges,
            ref TOKEN_PRIVILEGES NewState, int BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

        /// <summary>
        /// 特権名から LUID を取得します（LookupPrivilegeValue）。
        /// </summary>
        /// <param name="lpSystemName">システム名（通常 null）。</param>
        /// <param name="lpName">特権の名前（例: SeAssignPrimaryTokenPrivilege）。</param>
        /// <param name="lpLuid">取得された LUID（出力）。</param>
        /// <returns>成功したら true。</returns>
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

        /// <summary>
        /// ハンドルを閉じます（CloseHandle）。
        /// </summary>
        /// <param name="hObject">閉じるハンドル。</param>
        /// <returns>成功したら true。</returns>
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool CloseHandle(IntPtr hObject);

        /// <summary>
        /// セッション情報構造体（WTS_SESSION_INFO）を表します。
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        struct WTS_SESSION_INFO { public uint SessionID; public IntPtr pWinStationName; public int State; }

        // 物理コンソールのセッション ID を取得
        [DllImport("kernel32.dll")]
        static extern uint WTSGetActiveConsoleSessionId();

        // WTS_CONNECTSTATE_CLASS の値（読みやすさのため）
        const int WTSActive = 0; // enum WTS_CONNECTSTATE_CLASS
        const int WTSConnected = 1;
        const int WTSConnectQuery = 2;
        const int WTSShadow = 3;
        const int WTSDisconnected = 4;
        const int WTSIdle = 5;
        const int WTSListen = 6;
        const int WTSReset = 7;
        const int WTSDown = 8;
        const int WTSInit = 9;

        /// <summary>
        /// CreateProcess 系 API に渡す STARTUPINFO を表します。
        /// </summary>
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct STARTUPINFO
        {
            public int cb; public string lpReserved; public string lpDesktop; public string lpTitle;
            public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags; public short wShowWindow, cbReserved2;
            public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
        }

        /// <summary>
        /// CreateProcessAsUser の出力で返されるプロセス情報を表します。
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public int dwProcessId, dwThreadId; }

        /// <summary>
        /// LUID 構造体（特権識別子）を表します。
        /// </summary>
        [StructLayout(LayoutKind.Sequential)] struct LUID { public uint LowPart; public int HighPart; }

        /// <summary>
        /// トークン特権構造体（AdjustTokenPrivileges 用）。
        /// </summary>
        [StructLayout(LayoutKind.Sequential)] struct TOKEN_PRIVILEGES { public int PrivilegeCount; public LUID Luid; public int Attributes; }

        /// <summary>特権が有効であることを示すフラグ。</summary>
        const int SE_PRIVILEGE_ENABLED = 0x2;

        /// <summary>SeAssignPrimaryTokenPrivilege 特権名。</summary>
        const string SE_ASSIGNPRIMARYTOKEN_NAME = "SeAssignPrimaryTokenPrivilege";
        /// <summary>SeIncreaseQuotaPrivilege 特権名。</summary>
        const string SE_INCREASE_QUOTA_NAME = "SeIncreaseQuotaPrivilege";

        /// <summary>トークン操作に必要なアクセスフラグ（TOKEN_ASSIGN_PRIMARY など）</summary>
        const uint TOKEN_ASSIGN_PRIMARY = 0x0001, TOKEN_DUPLICATE = 0x0002, TOKEN_QUERY = 0x0008,
                   TOKEN_ADJUST_PRIVILEGES = 0x0020, TOKEN_ADJUST_DEFAULT = 0x0080, TOKEN_ADJUST_SESSIONID = 0x0100;

        /// <summary>トークンに必要な全アクセス（ユーティリティ用）。</summary>
        const uint TOKEN_ALL_REQUIRED = TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY |
                                        TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID;

        /// <summary>Unicode 環境を作成するフラグ（CreateProcessAsUser 用）。</summary>
        const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;

        /// <summary>
        /// トークン情報を取得します（GetTokenInformation）。
        /// </summary>
        /// <param name="TokenHandle">トークンハンドル。</param>
        /// <param name="TokenInformationClass">情報クラス（例: TokenUser = 1）。</param>
        /// <param name="TokenInformation">出力バッファ。</param>
        /// <param name="TokenInformationLength">バッファ長。</param>
        /// <param name="ReturnLength">返却長（出力）。</param>
        /// <returns>成功したら true。</returns>
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool GetTokenInformation(IntPtr TokenHandle, int TokenInformationClass,
            IntPtr TokenInformation, int TokenInformationLength, out int ReturnLength);

        /// <summary>
        /// SID からアカウント名を検索します（LookupAccountSid）。
        /// </summary>
        /// <param name="lpSystemName">システム名（通常 null）。</param>
        /// <param name="Sid">検索する SID。</param>
        /// <param name="Name">ユーザー名（出力バッファ）。</param>
        /// <param name="cchName">ユーザー名バッファ長（入出力）。</param>
        /// <param name="ReferencedDomainName">ドメイン名（出力バッファ）。</param>
        /// <param name="cchReferencedDomainName">ドメイン名バッファ長（入出力）。</param>
        /// <param name="peUse">アカウントタイプ（出力）。</param>
        /// <returns>成功したら true。</returns>
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool LookupAccountSid(string lpSystemName, IntPtr Sid,
            System.Text.StringBuilder Name, ref int cchName,
            System.Text.StringBuilder ReferencedDomainName, ref int cchReferencedDomainName,
            out int peUse);

        /// <summary>
        /// トークンからユーザー名（DOMAIN\user）を取得します。
        /// </summary>
        /// <param name="token">トークンハンドル。</param>
        /// <returns>成功すれば "DOMAIN\user"、失敗時はエラーメッセージ文字列を返します。</returns>
        static string GetUserFromToken(IntPtr token)
        {
            const int TokenUser = 1;
            GetTokenInformation(token, TokenUser, IntPtr.Zero, 0, out int len);
            IntPtr buffer = Marshal.AllocHGlobal(len);
            try
            {
                if (!GetTokenInformation(token, TokenUser, buffer, len, out _))
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "GetTokenInformation");

                IntPtr pSid = Marshal.ReadIntPtr(buffer);
                var name = new System.Text.StringBuilder(64);
                var domain = new System.Text.StringBuilder(64);
                int cchName = name.Capacity, cchDomain = domain.Capacity;
                int peUse;
                if (LookupAccountSid(null, pSid, name, ref cchName, domain, ref cchDomain, out peUse))
                    return $"{domain}\\{name}";
                else
                    return "(ユーザー名取得失敗)";
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        /// <summary>
        /// 指定した特権を現在のプロセスのトークン上で有効化します。
        /// </summary>
        /// <param name="name">有効化する特権名（例: SeAssignPrimaryTokenPrivilege）。</param>
        /// <remarks>
        /// 失敗した場合は Win32 例外をスローします。OpenProcessToken, LookupPrivilegeValue, AdjustTokenPrivileges を内部で使用します。
        /// </remarks>
        static void EnablePrivilege(string name)
        {
            if (!OpenProcessToken(Process.GetCurrentProcess().Handle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out var hTok))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "OpenProcessToken");
            try
            {
                if (!LookupPrivilegeValue(null, name, out var luid))
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "LookupPrivilegeValue " + name);
                var tp = new TOKEN_PRIVILEGES { PrivilegeCount = 1, Luid = luid, Attributes = SE_PRIVILEGE_ENABLED };
                if (!AdjustTokenPrivileges(hTok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "AdjustTokenPrivileges " + name);
            }
            finally { CloseHandle(hTok); }
        }

        /// <summary>
        /// アクティブなログインユーザーのセッションで指定のコマンドラインを実行します。
        /// </summary>
        /// <param name="commandLine">実行するコマンドライン（引用符などは呼び出し側で適切に付与してください）。</param>
        /// <param name="workingDir">プロセスのカレントディレクトリ（省略可）。</param>
        /// <exception cref="System.ComponentModel.Win32Exception">内部の Win32 API 呼び出しが失敗した場合。</exception>
        /// <exception cref="InvalidOperationException">アクティブセッションが見つからなかった場合。</exception>
        /// <remarks>
        /// 処理の流れ:
        /// 1) 必要特権を有効化（SeAssignPrimaryTokenPrivilege, SeIncreaseQuotaPrivilege）
        /// 2) WTSEnumerateSessions によりアクティブセッションを検索
        /// 3) WTSQueryUserToken でトークンを取得
        /// 4) DuplicateTokenEx / CreateEnvironmentBlock / CreateProcessAsUser によりユーザーセッション内で起動
        /// リモートデスクトップ (RDP) セッションも対象になります。
        /// </remarks>
        public static void RunForActiveUser(string commandLine, string workingDir = null)
        {
            // 1) 必要特権を有効化
            EnablePrivilege(SE_ASSIGNPRIMARYTOKEN_NAME);
            EnablePrivilege(SE_INCREASE_QUOTA_NAME);

            // 2) 起動候補となるユーザーセッションを収集（Active / Connected / Disconnected）
            if (!WTSEnumerateSessions(IntPtr.Zero, 0, 1, out var pInfo, out var count))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "WTSEnumerateSessions");

            // 状態と一緒に保持して優先度付けできるようにする
            var candidates = new List<(uint sid, int state)>();
            try
            {
                int size = Marshal.SizeOf(typeof(WTS_SESSION_INFO));
                for (int i = 0; i < count; i++)
                {
                    var si = Marshal.PtrToStructure<WTS_SESSION_INFO>(pInfo + i * size);

                    // サービスの session 0 は基本除外（必要なら条件を調整）
                    if (si.SessionID == 0)
                        continue;

                    // 起動候補に含める状態を列挙
                    if (si.State == WTSActive || si.State == WTSConnected || si.State == WTSDisconnected)
                    {
                        candidates.Add((si.SessionID, si.State));
                    }
                }
            }
            finally { WTSFreeMemory(pInfo); }

            if (candidates.Count == 0)
                throw new InvalidOperationException("起動候補となるユーザーセッションが見つかりません。");

            // 物理コンソールセッションを最優先（存在して候補に含まれていれば先頭へ）
            uint consoleSid = WTSGetActiveConsoleSessionId();
            if (consoleSid != 0xFFFFFFFF)
            {
                int idx = candidates.FindIndex(c => c.sid == consoleSid);
                if (idx >= 0)
                {
                    var c = candidates[idx];
                    candidates.RemoveAt(idx);
                    candidates.Insert(0, c);
                }
            }

            // 状態ごとの優先度（小さいほど優先）
            int StatePriority(int state)
            {
                switch (state)
                {
                    case WTSActive: return 0; // 最優先：アクティブ
                    case WTSConnected: return 1; // 次点：接続済み
                    case WTSDisconnected: return 2; // 切断済み
                    default: return 99;
                }
            }

            // 同一セッションの重複を排除しつつ優先度で整列
            candidates = candidates
                .GroupBy(c => c.sid)
                .Select(g => g.First())            // 同一 sid は最初のものを採用
                .OrderBy(c => StatePriority(c.state))
                .ToList();

            // 3) 候補を上から順にトークン取得を試す
            IntPtr userToken = IntPtr.Zero;
            uint selectedSid = 0xFFFFFFFF;

            foreach (var c in candidates)
            {
                if (WTSQueryUserToken(c.sid, out userToken))
                {
                    selectedSid = c.sid;
                    break;
                }
                else
                {
                    int err = Marshal.GetLastWin32Error();
                    try { EventLog.WriteEntry("BridgeExec", $"WTSQueryUserToken 失敗: Session={c.sid}, State={c.state}, Error={err}", EventLogEntryType.Warning); } catch { }
                }
            }

            // 取得できなければ終了
            if (userToken == IntPtr.Zero || selectedSid == 0xFFFFFFFF)
                throw new InvalidOperationException("ユーザーセッションのトークン取得に失敗しました（Active/Connected/Disconnected いずれも不可）。");

            // （参考）誰のトークンか出力
            Console.WriteLine($"ターゲットセッション: {selectedSid} / 実行ユーザー: {GetUserFromToken(userToken)}");

            IntPtr primary = IntPtr.Zero, env = IntPtr.Zero;
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            try
            {
                if (!DuplicateTokenEx(userToken, TOKEN_ALL_REQUIRED, IntPtr.Zero, 2 /*Impersonation*/, 1 /*Primary*/, out primary))
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "DuplicateTokenEx");

                if (!CreateEnvironmentBlock(out env, primary, false))
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "CreateEnvironmentBlock");

                var si = new STARTUPINFO { cb = Marshal.SizeOf<STARTUPINFO>(), lpDesktop = @"winsta0\default" };
                if (!CreateProcessAsUser(primary, null, commandLine, IntPtr.Zero, IntPtr.Zero, false,
                                         CREATE_UNICODE_ENVIRONMENT, env, workingDir, ref si, out pi))
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "CreateProcessAsUser");
            }
            finally
            {
                if (pi.hThread != IntPtr.Zero) CloseHandle(pi.hThread);
                if (pi.hProcess != IntPtr.Zero) CloseHandle(pi.hProcess);
                if (env != IntPtr.Zero) DestroyEnvironmentBlock(env);
                if (primary != IntPtr.Zero) CloseHandle(primary);
                if (userToken != IntPtr.Zero) CloseHandle(userToken);
            }
        }

        /// <summary>
        /// エントリポイント。現在の実行ユーザーが SYSTEM または 管理者でなければ終了します。
        /// サービスからの起動を想定。成功/失敗に関わらず確実に終了。
        /// </summary>
        /// <remarks>
        /// サンプルとしてログインユーザー側で cscript による VBS 実行を要求するコードを含みます。
        /// 実運用では引数処理やログ出力拡張、エラーハンドリング強化等を追加してください。
        /// </remarks>
        static void Main()
        {
            // === Watchdog (専用スレッド + WaitHandle) ===
            TimeSpan WATCHDOG_TIMEOUT = TimeSpan.FromMinutes(10); // ←調整可
            var watchdogCancel = new ManualResetEvent(false);

            var watchdogThread = new Thread(() =>
            {
                try
                {
                    // 規定時間内にキャンセルが来なければタイムアウト
                    bool cancelled = watchdogCancel.WaitOne(WATCHDOG_TIMEOUT);
                    if (!cancelled)
                    {
                        try { EventLog.WriteEntry("BridgeExec", $"Watchdog timeout ({WATCHDOG_TIMEOUT}). 強制終了します。", EventLogEntryType.Error); } catch { }
                        try { Process.GetCurrentProcess().Kill(); } catch { Environment.FailFast("Watchdog timeout (Kill failed)"); }
                    }
                }
                catch
                {
                    // ここでの例外は握りつぶす（とにかくプロセスを落とすのが目的）
                }
            })
            {
                IsBackground = true,
                Name = "BridgeExec.Watchdog"
            };
            watchdogThread.Start();
            // ===========================================

            // グローバル例外ハンドラ（確実に Exit）
            AppDomain.CurrentDomain.UnhandledException += (s, e) =>
            {
                try { EventLog.WriteEntry("BridgeExec", $"未処理例外: {e.ExceptionObject}", EventLogEntryType.Error); } catch { }
                _exitCode = EXIT_RUNTIME_ERROR;
                Environment.Exit(_exitCode);
            };
            TaskScheduler.UnobservedTaskException += (s, e) =>
            {
                e.SetObserved();
                try { EventLog.WriteEntry("BridgeExec", $"未監視タスク例外: {e.Exception}", EventLogEntryType.Error); } catch { }
                _exitCode = EXIT_RUNTIME_ERROR;
                Environment.Exit(_exitCode);
            };

            try
            {
                // 権限チェック（SYSTEM or 管理者）:contentReference[oaicite:3]{index=3}
                using (var identity = WindowsIdentity.GetCurrent())
                {
                    string name = identity.Name;
                    bool isSystem = string.Equals(name, "NT AUTHORITY\\SYSTEM", StringComparison.OrdinalIgnoreCase);
                    bool isAdmin = new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);

                    if (!(isSystem || isAdmin))
                    {
                        try { EventLog.WriteEntry("BridgeExec", $"アクセス拒否: 実行ユーザー={name}", EventLogEntryType.Warning); } catch { }
                        Console.Error.WriteLine($"Access denied: 実行ユーザー={name}");
                        _exitCode = EXIT_ACCESS_DENIED;
                        return; // finally で確実に Exit される
                    }
                }

                // 例：ログインユーザー側で cscript + VBS を実行（必要に応じて差し替え）:contentReference[oaicite:4]{index=4}
                string cscript = Environment.ExpandEnvironmentVariables(@"%SystemRoot%\System32\cscript.exe");
                string script = @"C:\Scripts\myscript.vbs";
                RunForActiveUser($"\"{cscript}\" //nologo \"{script}\"", @"C:\Scripts");

                Console.WriteLine("起動要求OK");
                _exitCode = EXIT_SUCCESS;
            }
            catch (Exception ex)
            {
                try { EventLog.WriteEntry("BridgeExec", $"実行エラー: {ex}", EventLogEntryType.Error); } catch { }
                _exitCode = (_exitCode == EXIT_ACCESS_DENIED) ? _exitCode : EXIT_RUNTIME_ERROR;
            }
            finally
            {
                // 正常／異常終了に関わらずウォッチドッグを停止
                try
                {
                    watchdogCancel.Set();
                    // バックグラウンドとはいえ、念のため短時間 join
                    watchdogThread.Join(2000);
                }
                catch { }

                // 必ず終了
                Environment.Exit(_exitCode);
            }
        }
    }
}
