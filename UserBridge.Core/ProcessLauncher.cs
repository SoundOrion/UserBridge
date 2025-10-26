using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using static UserBridge.Core.Interop;

namespace UserBridge.Core
{
    public static class ProcessLauncher
    {
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
            TokenUtilities.EnablePrivilege(SE_ASSIGNPRIMARYTOKEN_NAME);
            TokenUtilities.EnablePrivilege(SE_INCREASE_QUOTA_NAME);

            // 2) アクティブなユーザーセッションを探す（RDP含む）
            if (!WTSEnumerateSessions(IntPtr.Zero, 0, 1, out var pInfo, out var count))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "WTSEnumerateSessions");
            uint targetSid = 0xFFFFFFFF;
            try
            {
                int size = Marshal.SizeOf(typeof(WTS_SESSION_INFO));
                for (int i = 0; i < count; i++)
                {
                    var si = Marshal.PtrToStructure<WTS_SESSION_INFO>(pInfo + i * size);
                    if (si.State == WTSActive) { targetSid = si.SessionID; break; }
                }
            }
            finally { WTSFreeMemory(pInfo); }

            if (targetSid == 0xFFFFFFFF)
                throw new InvalidOperationException("アクティブなユーザーセッションが見つかりません。");

            // 3) そのセッションのユーザートークン取得
            if (!WTSQueryUserToken(targetSid, out var userToken))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "WTSQueryUserToken");

            //Console.WriteLine($"実行ユーザー: {TokenUtilities.GetUserFromToken(userToken)}");

            IntPtr primary = IntPtr.Zero;
            IntPtr env = IntPtr.Zero;
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            try
            {
                // 4) Primary トークンへ複製
                if (!DuplicateTokenEx(userToken, TOKEN_ALL_REQUIRED, IntPtr.Zero, 2 /*Impersonation*/, 1 /*Primary*/, out primary))
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "DuplicateTokenEx");

                // 5) 環境ブロック作成（ユーザー環境）
                if (!CreateEnvironmentBlock(out env, primary, false))
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "CreateEnvironmentBlock");

                // 6) ユーザーセッションでプロセス作成
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

        public static int RunForActiveUserAndWait(string commandLine, string workingDir, TimeSpan? timeout = null)
        {
            // 1) 必要特権を有効化
            TokenUtilities.EnablePrivilege(SE_ASSIGNPRIMARYTOKEN_NAME);
            TokenUtilities.EnablePrivilege(SE_INCREASE_QUOTA_NAME);

            // 2) アクティブなユーザーセッションを探す（RDP含む）
            if (!WTSEnumerateSessions(IntPtr.Zero, 0, 1, out var pInfo, out var count))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "WTSEnumerateSessions");
            uint targetSid = 0xFFFFFFFF;
            try
            {
                int size = Marshal.SizeOf(typeof(WTS_SESSION_INFO));
                for (int i = 0; i < count; i++)
                {
                    var si = Marshal.PtrToStructure<WTS_SESSION_INFO>(pInfo + i * size);
                    if (si.State == WTSActive) { targetSid = si.SessionID; break; }
                }
            }
            finally { WTSFreeMemory(pInfo); }

            if (targetSid == 0xFFFFFFFF)
                throw new InvalidOperationException("アクティブなユーザーセッションが見つかりません。");

            // 3) そのセッションのユーザートークン取得
            if (!WTSQueryUserToken(targetSid, out var userToken))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "WTSQueryUserToken");

            //Console.WriteLine($"実行ユーザー: {TokenUtilities.GetUserFromToken(userToken)}");

            IntPtr primary = IntPtr.Zero;
            IntPtr env = IntPtr.Zero;
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            try
            {
                // 4) Primary トークンへ複製
                if (!DuplicateTokenEx(userToken, TOKEN_ALL_REQUIRED, IntPtr.Zero, 2 /*Impersonation*/, 1 /*Primary*/, out primary))
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "DuplicateTokenEx");

                // 5) 環境ブロック作成（ユーザー環境）
                if (!CreateEnvironmentBlock(out env, primary, false))
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "CreateEnvironmentBlock");

                // 6) ユーザーセッションでプロセス作成
                var si = new STARTUPINFO { cb = Marshal.SizeOf<STARTUPINFO>(), lpDesktop = @"winsta0\default" };

                if (!CreateProcessAsUser(primary, null, commandLine, IntPtr.Zero, IntPtr.Zero, false,
                                         CREATE_UNICODE_ENVIRONMENT, env, workingDir, ref si, out pi))
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "CreateProcessAsUser");

                // 7) 待機（タイムアウト対応）
                uint ms = timeout.HasValue
                    ? (uint)Math.Min(Math.Max(timeout.Value.TotalMilliseconds, 0), int.MaxValue)
                    : INFINITE;

                uint w = WaitForSingleObject(pi.hProcess, ms);
                //if (w == WAIT_TIMEOUT)
                //    throw new TimeoutException("ユーザー側プロセスがタイムアウトしました。");
                if (w == WAIT_TIMEOUT)
                {
                    var timeoutExitCode = 6;
                    TerminateProcess(pi.hProcess, (uint)timeoutExitCode);
                    WaitForSingleObject(pi.hProcess, 30_000); // 念のため終了待ち
                    return timeoutExitCode;
                }

                if (w == WAIT_FAILED)
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "WaitForSingleObject");

                // WAIT_OBJECT_0 or WAIT_ABANDONED（通常は前者）
                if (!GetExitCodeProcess(pi.hProcess, out uint code))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "GetExitCodeProcess");

                // 理論上ここで STILL_ACTIVE は来ないが、保険で補正
                if (code == STILL_ACTIVE && w == WAIT_OBJECT_0)
                    code = 0;

                return unchecked((int)code);
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
    }
}
