// =====================================
// UserBridge.Client/Program.cs（都度起動 → 接続 → 1往復 → 終了）
// =====================================
using System;
using System.IO;
using System.IO.Pipes;
using System.Threading.Tasks;
using UserBridge.Shared;


namespace UserBridge.Client
{
    internal class Program
    {
        static async Task<int> Main(string[] args)
        {
            string pipeName = BridgeConstants.PipeName;
            for (int i = 0; i + 1 < args.Length; i++)
            {
                if (args[i] == "--pipe") pipeName = args[i + 1];
            }


            Console.WriteLine($"[Client] 起動（pipe={pipeName}）");
            try
            {
                using var client = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut);
                await client.ConnectAsync(5000); // 5秒で接続
                using var writer = new StreamWriter(client) { AutoFlush = true };
                using var reader = new StreamReader(client);


                // 受信 → 応答
                string? msg = await reader.ReadLineAsync();
                Console.WriteLine("[Client] 受信: " + (msg ?? "<null>"));
                await writer.WriteLineAsync("ユーザー側：OK、処理開始");
                Console.WriteLine("[Client] 応答送信");
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("[Client] エラー: " + ex.Message);
                return 1;
            }
        }
    }
}