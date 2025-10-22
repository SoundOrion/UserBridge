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