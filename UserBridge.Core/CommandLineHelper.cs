using System;
using System.Collections.Generic;
using System.IO;

namespace UserBridge.Core
{
    /// <summary>
    /// スクリプトまたは実行ファイルを起動するためのコマンドラインを構築するヘルパクラス。
    /// </summary>
    /// <remarks>
    /// 指定されたスクリプトの拡張子（.vbs / .ps1 / .bat / .exe）に応じて、
    /// 適切な実行コマンドラインを生成します。
    /// </remarks>
    public static class CommandLineHelper
    {
        /// <summary>
        /// スクリプトや実行ファイルのパスを基に、起動に適したコマンドライン文字列を生成します。
        /// </summary>
        /// <param name="scriptPath">スクリプトまたは実行ファイルのフルパス。</param>
        /// <param name="args">引数（任意）。</param>
        /// <returns>実行可能なコマンドライン文字列。</returns>
        /// <exception cref="NotSupportedException">未知の拡張子の場合にスローされます。</exception>
        public static string BuildCommand(string scriptPath, IEnumerable<string> args = null)
        {
            if (string.IsNullOrWhiteSpace(scriptPath))
                throw new ArgumentException("scriptPath が無効です。", nameof(scriptPath));

            string extension = Path.GetExtension(scriptPath).ToLowerInvariant();
            string arguments = args != null ? string.Join(" ", args) : string.Empty;

            switch (extension)
            {
                case ".exe":
                    return $"\"{scriptPath}\" {arguments}".Trim();

                case ".bat":
                case ".cmd":
                    return $"cmd.exe /c \"{scriptPath}\" {arguments}".Trim();

                case ".ps1":
                    string psExe = Environment.ExpandEnvironmentVariables(@"%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
                    return $"\"{psExe}\" -NoProfile -ExecutionPolicy Bypass -File \"{scriptPath}\" {arguments}".Trim();

                case ".vbs":
                    string csExe = Environment.ExpandEnvironmentVariables(@"%SystemRoot%\\System32\\cscript.exe");
                    return $"\"{csExe}\" //nologo \"{scriptPath}\" {arguments}".Trim();

                default:
                    throw new NotSupportedException($"拡張子 '{extension}' はサポートされていません。");
            }
        }
    }
}
