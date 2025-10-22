using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using static UserBridge.Core.Interop;

namespace UserBridge.Core
{
    public static class TokenUtilities
    {
        /// <summary>
        /// 指定した特権を現在のプロセスのトークン上で有効化します。
        /// </summary>
        /// <param name="name">有効化する特権名（例: SeAssignPrimaryTokenPrivilege）。</param>
        /// <remarks>
        /// 失敗した場合は Win32 例外をスローします。OpenProcessToken, LookupPrivilegeValue, AdjustTokenPrivileges を内部で使用します。
        /// </remarks>
        public static void EnablePrivilege(string name)
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

        public static string GetUserFromToken(IntPtr token)
        {
            const int TokenUser = 1;
            Interop.GetTokenInformation(token, TokenUser, IntPtr.Zero, 0, out int len);
            IntPtr buffer = Marshal.AllocHGlobal(len);
            try
            {
                if (!Interop.GetTokenInformation(token, TokenUser, buffer, len, out _))
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "GetTokenInformation");

                IntPtr pSid = Marshal.ReadIntPtr(buffer);
                var name = new StringBuilder(64);
                var domain = new StringBuilder(64);
                int cchName = name.Capacity, cchDomain = domain.Capacity;
                int peUse;
                if (Interop.LookupAccountSid(null, pSid, name, ref cchName, domain, ref cchDomain, out peUse))
                    return $"{domain}\\{name}";
                return "(ユーザー名取得失敗)";
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }

        public static IntPtr DuplicatePrimary(IntPtr userToken)
        {
            if (!Interop.DuplicateTokenEx(userToken, Interop.TOKEN_ALL_REQUIRED, IntPtr.Zero, 2 /*Impersonation*/, 1 /*Primary*/, out var primary))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "DuplicateTokenEx");
            return primary;
        }
    }
}

