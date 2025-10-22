using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace UserBridge.Core
{
    /// <summary>
    /// アクティブなログインユーザーセッションを検出するためのユーティリティクラス。
    /// </summary>
    /// <remarks>
    /// Windows Terminal Services (WTS) API を利用して現在のシステム上でログインしているセッション情報を列挙し、
    /// 最初に <c>WTSActive</c> 状態のセッションを検出してそのセッションIDを返します。
    /// 主に <see cref="ProcessLauncher.RunForActiveUser"/> 内で使用され、
    /// SYSTEM/管理者プロセスがアクティブユーザーセッションでプロセスを作成するための前提情報を取得します。
    /// </remarks>
    public static class SessionUtilities
    {
        /// <summary>
        /// 現在アクティブな（ログイン済み）ユーザーセッションの ID を取得します。
        /// </summary>
        /// <returns>アクティブセッションの <see cref="uint"/> 型 ID。</returns>
        /// <exception cref="Win32Exception">セッション列挙 API 呼び出しに失敗した場合。</exception>
        /// <exception cref="InvalidOperationException">アクティブなユーザーセッションが見つからなかった場合。</exception>
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

