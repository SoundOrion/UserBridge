using System;
using System.Runtime.InteropServices;

namespace UserBridge.Core
{
    internal static class Interop
    {
        // --- WTS ---
        [DllImport("wtsapi32.dll", SetLastError = true)]
        internal static extern bool WTSEnumerateSessions(IntPtr hServer, int Reserved, int Version,
            out IntPtr ppSessionInfo, out int pCount);

        [DllImport("wtsapi32.dll")]
        internal static extern void WTSFreeMemory(IntPtr pMemory);

        [DllImport("wtsapi32.dll", SetLastError = true)]
        internal static extern bool WTSQueryUserToken(uint SessionId, out IntPtr phToken);

        [StructLayout(LayoutKind.Sequential)]
        internal struct WTS_SESSION_INFO { public uint SessionID; public IntPtr pWinStationName; public int State; }
        internal const int WTSActive = 0; // WTS_CONNECTSTATE_CLASS

        // --- Advapi32 ---
        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes,
            int SecurityImpersonationLevel, int TokenType, out IntPtr phNewToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges,
            ref TOKEN_PRIVILEGES NewState, int BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

        /// <summary>
        /// 特権名から LUID を取得します（LookupPrivilegeValue）。
        /// </summary>
        /// <param name="lpSystemName">システム名（通常 null）。</param>
        /// <param name="lpName">特権の名前（例: SeAssignPrimaryTokenPrivilege）。</param>
        /// <param name="lpLuid">取得された LUID（出力）。</param>
        /// <returns>成功したら true。</returns>
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool GetTokenInformation(IntPtr TokenHandle, int TokenInformationClass,
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
        internal static extern bool LookupAccountSid(string lpSystemName, IntPtr Sid,
            System.Text.StringBuilder Name, ref int cchName,
            System.Text.StringBuilder ReferencedDomainName, ref int cchReferencedDomainName,
            out int peUse);

        [StructLayout(LayoutKind.Sequential)]
        internal struct LUID { public uint LowPart; public int HighPart; }

        [StructLayout(LayoutKind.Sequential)]
        internal struct TOKEN_PRIVILEGES { public int PrivilegeCount; public LUID Luid; public int Attributes; }

        internal const int SE_PRIVILEGE_ENABLED = 0x2;
        internal const string SE_ASSIGNPRIMARYTOKEN_NAME = "SeAssignPrimaryTokenPrivilege";
        internal const string SE_INCREASE_QUOTA_NAME = "SeIncreaseQuotaPrivilege";

        internal const uint TOKEN_ASSIGN_PRIMARY = 0x0001, TOKEN_DUPLICATE = 0x0002, TOKEN_QUERY = 0x0008,
                         TOKEN_ADJUST_PRIVILEGES = 0x0020, TOKEN_ADJUST_DEFAULT = 0x0080, TOKEN_ADJUST_SESSIONID = 0x0100;
        internal const uint TOKEN_ALL_REQUIRED = TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY |
                                                TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID;

        // --- userenv ---
        [DllImport("userenv.dll", SetLastError = true)]
        internal static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

        [DllImport("userenv.dll", SetLastError = true)]
        internal static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

        // --- kernel32 ---

        /// <summary>
        /// ハンドルを閉じます（CloseHandle）。
        /// </summary>
        /// <param name="hObject">閉じるハンドル。</param>
        /// <returns>成功したら true。</returns>
        [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

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
        internal static extern bool CreateProcessAsUser(IntPtr hToken, string lpApplicationName, string lpCommandLine,
            IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags,
            IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        /// <summary>
        /// CreateProcess 系 API に渡す STARTUPINFO を表します。
        /// </summary>
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct STARTUPINFO
        {
            public int cb; public string lpReserved; public string lpDesktop; public string lpTitle;
            public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags; public short wShowWindow, cbReserved2;
            public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public int dwProcessId, dwThreadId; }

        internal const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;

        // ===== Win32 定数 =====
        internal const uint INFINITE = 0xFFFFFFFF;
        internal const uint WAIT_OBJECT_0 = 0x00000000;
        internal const uint WAIT_ABANDONED = 0x00000080;
        internal const uint WAIT_TIMEOUT = 0x00000102;
        internal const uint WAIT_FAILED = 0xFFFFFFFF;
        internal const uint STILL_ACTIVE = 259;
    }
}
