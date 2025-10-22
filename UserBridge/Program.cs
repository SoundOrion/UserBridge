using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace UserBridge
{
    internal class Program
    {
        // ===== P/Invoke =====
        [DllImport("wtsapi32.dll", SetLastError = true)]
        static extern bool WTSEnumerateSessions(IntPtr hServer, int Reserved, int Version,
            out IntPtr ppSessionInfo, out int pCount);

        [DllImport("wtsapi32.dll")] static extern void WTSFreeMemory(IntPtr pMemory);

        [DllImport("wtsapi32.dll", SetLastError = true)]
        static extern bool WTSQueryUserToken(uint SessionId, out IntPtr phToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes,
            int SecurityImpersonationLevel, int TokenType, out IntPtr phNewToken);

        [DllImport("userenv.dll", SetLastError = true)]
        static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

        [DllImport("userenv.dll", SetLastError = true)]
        static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool CreateProcessAsUser(IntPtr hToken, string lpApplicationName, string lpCommandLine,
            IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags,
            IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges,
            ref TOKEN_PRIVILEGES NewState, int BufferLength, IntPtr PreviousState, IntPtr ReturnLength);
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

        [DllImport("kernel32.dll", SetLastError = true)] static extern bool CloseHandle(IntPtr hObject);

        [StructLayout(LayoutKind.Sequential)]
        struct WTS_SESSION_INFO { public uint SessionID; public IntPtr pWinStationName; public int State; }
        const int WTSActive = 0; // enum WTS_CONNECTSTATE_CLASS

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct STARTUPINFO
        {
            public int cb; public string lpReserved; public string lpDesktop; public string lpTitle;
            public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags; public short wShowWindow, cbReserved2;
            public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public int dwProcessId, dwThreadId; }

        [StructLayout(LayoutKind.Sequential)] struct LUID { public uint LowPart; public int HighPart; }
        [StructLayout(LayoutKind.Sequential)] struct TOKEN_PRIVILEGES { public int PrivilegeCount; public LUID Luid; public int Attributes; }
        const int SE_PRIVILEGE_ENABLED = 0x2;
        const string SE_ASSIGNPRIMARYTOKEN_NAME = "SeAssignPrimaryTokenPrivilege";
        const string SE_INCREASE_QUOTA_NAME = "SeIncreaseQuotaPrivilege";

        const uint TOKEN_ASSIGN_PRIMARY = 0x0001, TOKEN_DUPLICATE = 0x0002, TOKEN_QUERY = 0x0008,
                   TOKEN_ADJUST_PRIVILEGES = 0x0020, TOKEN_ADJUST_DEFAULT = 0x0080, TOKEN_ADJUST_SESSIONID = 0x0100;
        const uint TOKEN_ALL_REQUIRED = TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY |
                                        TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID;

        const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool GetTokenInformation(IntPtr TokenHandle, int TokenInformationClass,
            IntPtr TokenInformation, int TokenInformationLength, out int ReturnLength);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool LookupAccountSid(string lpSystemName, IntPtr Sid,
            System.Text.StringBuilder Name, ref int cchName,
            System.Text.StringBuilder ReferencedDomainName, ref int cchReferencedDomainName,
            out int peUse);

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

        public static void RunForActiveUser(string commandLine, string workingDir = null)
        {
            // 1) 必要特権を有効化
            EnablePrivilege(SE_ASSIGNPRIMARYTOKEN_NAME);
            EnablePrivilege(SE_INCREASE_QUOTA_NAME);

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

            Console.WriteLine($"実行ユーザー: {GetUserFromToken(userToken)}");

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

        static void Main()
        {
            using (var identity = WindowsIdentity.GetCurrent())
            {
                string name = identity.Name;
                bool isSystem = string.Equals(name, "NT AUTHORITY\\SYSTEM", StringComparison.OrdinalIgnoreCase);
                bool isAdmin = new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);

                if (!(isSystem || isAdmin))
                {
                    EventLog.WriteEntry("BridgeExec",
                        $"アクセス拒否: 実行ユーザー={name}",
                        EventLogEntryType.Warning);

                    Console.Error.WriteLine($"Access denied: 実行ユーザー={name}");
                    Environment.Exit(1);
                }
            }

            // 例：ログインユーザー側で cscript + VBS を実行
            string cscript = Environment.ExpandEnvironmentVariables(@"%SystemRoot%\System32\cscript.exe");
            string script = @"C:\Scripts\myscript.vbs";
            RunForActiveUser($"\"{cscript}\" //nologo \"{script}\"", @"C:\Scripts");
            Console.WriteLine("起動要求OK");
        }
    }
}
