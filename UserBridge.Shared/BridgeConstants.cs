// =====================================
// 共通：パイプ名（必要なら共有定数クラスに）
// =====================================
namespace UserBridge.Shared
{
    public static class BridgeConstants
    {
        // 実運用では GUID を含める等で一意性を高める。
        public const string PipeName = "UserBridgePipe";
    }
}