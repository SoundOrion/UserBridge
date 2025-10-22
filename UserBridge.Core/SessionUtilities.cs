using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace UserBridge.Core
{
    public static class SessionUtilities
    {
        public static uint GetActiveSessionId()
        {
            if (!Interop.WTSEnumerateSessions(IntPtr.Zero, 0, 1, out var pInfo, out var count))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "WTSEnumerateSessions");
            try
            {
                int size = Marshal.SizeOf(typeof(Interop.WTS_SESSION_INFO));
                for (int i = 0; i < count; i++)
                {
                    var si = Marshal.PtrToStructure<Interop.WTS_SESSION_INFO>(pInfo + i * size);
                    if (si.State == Interop.WTSActive) return si.SessionID;
                }
            }
            finally { Interop.WTSFreeMemory(pInfo); }
            throw new InvalidOperationException("アクティブなユーザーセッションが見つかりません。");
        }
    }
}

