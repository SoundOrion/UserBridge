

`WTSActive` などは、**Windows Terminal Services (WTS)** API の列挙型 `WTS_CONNECTSTATE_CLASS` に対応しています。
これは「セッションが現在どんな状態か」を表すもので、`WTSEnumerateSessions` が返す構造体 `WTS_SESSION_INFO.State` に入っています。

---

## 🧩 各定数の意味（`WTS_CONNECTSTATE_CLASS`）

| 定数名                 |  値  | 状態の説明                                                                      |
| :------------------ | :-: | :------------------------------------------------------------------------- |
| **WTSActive**       |  0  | **アクティブなセッション**。現在ユーザーが実際に操作している（ログオン中で、フォーカスがある）状態。RDPやコンソールで操作中。         |
| **WTSConnected**    |  1  | 接続済みだが、現在はアクティブでない（バックグラウンドになっている）状態。例えば、別のユーザーがアクティブで、こっちは待機状態。           |
| **WTSConnectQuery** |  2  | セッションが接続要求中の状態。接続試行の途中（接続中）で安定していない。通常はほとんど見ない。                            |
| **WTSShadow**       |  3  | 他のセッションを「シャドウ」（リモート監視/共有）している状態。RDS 環境でのセッション監視時に使用。                       |
| **WTSDisconnected** |  4  | **切断状態**。ユーザーはログオン済みだが、接続が切れている（RDP切断など）。再接続すればセッションが再開される。← 今回あなたが拾いたい対象。 |
| **WTSIdle**         |  5  | 未使用セッション。端末がアイドル状態などで、誰も使っていない。                                            |
| **WTSListen**       |  6  | **リスニング状態**。リモート接続を待っているセッション（RDP接続受付用の「待機セッション」）。通常は触らない。                 |
| **WTSReset**        |  7  | セッションがリセット（再起動・再初期化）中。作成または削除途中。                                           |
| **WTSDown**         |  8  | セッションがダウン中（異常終了・シャットダウン処理中など）。ほぼ使えない。                                      |
| **WTSInit**         |  9  | 初期化中。セッション作成直後で、まだ完全に利用可能ではない。                                             |

---

## 💡 よく使う組み合わせ

実用上扱うのはほぼ以下の3つ：

```csharp
if (si.State == WTSActive || si.State == WTSConnected || si.State == WTSDisconnected)
{
    // 実際にユーザーがログオン済みで、再利用可能なセッション
}
```

* **Active**：現在ログオン中でフォアグラウンド。
* **Connected**：バックグラウンド（他ユーザーがアクティブな状態）だが、RDP経由などで有効。
* **Disconnected**：ユーザーがログオンしたまま切断。再接続で復帰可能。

これらが “ユーザーの存在するセッション” として安全にターゲットにできます。

---















## 本番稼働中
- プロジェクト: **B**
- 反映日: 2025-10-26
- 由来: `production.json` を参照
- 本番デプロイ先: <URLや環境名>
- 本番のコミット: `abcdef1`（リンク）

# 🧩 UserBridge

**UserBridge** は、`NT AUTHORITY\SYSTEM` または管理者権限で実行されたプロセスから、
現在アクティブなログインユーザー（RDP 含む）のセッション内で任意のコマンドを実行するための C# ユーティリティです。

---

## 🚀 概要

Windows 環境では、サービス（SYSTEM権限など）からユーザーのデスクトップ上でアプリやスクリプトを実行することは通常できません。
**UserBridge** はこの制約を超え、以下の手順で安全にユーザーセッションでのプロセス起動を実現します：

1. `WTSEnumerateSessions` によりアクティブなセッションを列挙
2. `WTSQueryUserToken` で対象ユーザーのトークンを取得
3. `DuplicateTokenEx` と `CreateEnvironmentBlock` により実行環境を構築
4. `CreateProcessAsUser` でユーザーセッション内に新プロセスを生成

結果として、サービス側からでも「ユーザーのデスクトップ上でプログラムを実行」できます。

---

## 🧰 主な機能

* SYSTEM / 管理者権限からのユーザーセッションプロセス実行
* `SeAssignPrimaryTokenPrivilege` / `SeIncreaseQuotaPrivilege` 特権の自動有効化
* 実行ユーザー名の自動取得と出力
* VBS や EXE、任意のコマンドライン実行に対応
* ログ（EventLog）出力によるアクセス制御通知

---

## 💻 使用例

`Main()` 内ではサンプルとして、ログイン中ユーザー側で VBScript を実行するコードが含まれています：

```csharp
string cscript = Environment.ExpandEnvironmentVariables(@"%SystemRoot%\System32\cscript.exe");
string script = @"C:\Scripts\myscript.vbs";
RunForActiveUser($"\"{cscript}\" //nologo \"{script}\"", @"C:\Scripts");
```

これにより、`C:\Scripts\myscript.vbs` がアクティブユーザーのデスクトップで実行されます。

---

## ⚙️ ビルド方法

```bash
git clone https://github.com/<yourname>/UserBridge.git
cd UserBridge
dotnet build -c Release
```

ビルド後、`UserBridge.exe` を **管理者または SYSTEM 権限** で実行してください。

---

## 🛡️ 注意事項

* `CreateProcessAsUser` による起動には **SeAssignPrimaryTokenPrivilege** と **SeIncreaseQuotaPrivilege** が必要です。
  SYSTEM または Local Administrator グループでの実行を推奨します。
* 対象環境：Windows 10 / 11 / Server 2016+
* セキュリティ上の理由から、ユーザー指定入力を直接 `commandLine` に渡さないよう注意してください。

---

## 📄 ライセンス

MIT License

---

## 🧠 参考情報

* [Microsoft Docs - CreateProcessAsUserW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
* [MSDN - WTSQueryUserToken function](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsqueryusertoken)