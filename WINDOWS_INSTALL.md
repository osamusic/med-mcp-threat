# Windows インストールガイド

## v0.3.0 必須依存関係の明確化

WindowsでModuleNotFoundErrorと`extract_data_types`で応答がない問題を解決しました。v0.3.0では：

- **必須依存関係**: sentence-transformersが必須（フォールバック機能を削除）
- **エラーハンドリング改善**: 詳細なエラー情報とタイムアウト対策
- **初期化ログ**: 正規化器の初期化状況を表示

## インストール手順

### 1. 既存のパッケージをアンインストール

```powershell
pip uninstall mcp-threat-extraction
```

### 2. 新しいパッケージをインストール

最新の自己完結型パッケージをダウンロードしてインストール：

```powershell
# 必須依存関係を先にインストール
pip install sentence-transformers

# dist/mcp_threat_extraction-0.3.0-py3-none-any.whl をダウンロード後
pip install mcp_threat_extraction-0.3.0-py3-none-any.whl
```

### 3. 環境変数の設定

```powershell
$env:OPENAI_API_KEY = "your-api-key"
$env:OPENAI_MODEL = "gpt-4"
```

または `.env` ファイルを作成:
```
OPENAI_API_KEY=your-api-key
OPENAI_MODEL=gpt-4
```

### 4. 動作確認

```powershell
mcp-threat-extraction
```

エラーが出なければ正常にインストールされています。

## Claude Desktopでの設定

`%APPDATA%\Claude\claude_desktop_config.json` に追加：

```json
{
  "mcpServers": {
    "threat-extraction": {
      "command": "mcp-threat-extraction",
      "env": {
        "OPENAI_API_KEY": "your-api-key",
        "OPENAI_MODEL": "gpt-4"
      }
    }
  }
}
```

## v0.3.0の変更点

- **必須依存関係**: sentence-transformersが必須（正確性を重視）
- **フォールバック削除**: 間違った結果を避けるためキーワードベース機能を削除
- **エラーハンドリング**: 詳細なデバッグ情報を追加
- **初期化ログ**: 正規化器の初期化時間を表示

## トラブルシューティング

### インポートエラーが発生する場合

1. パッケージが完全にアンインストールされているか確認
2. 新しいv1.1.0パッケージをインストール
3. Python環境を再起動

### APIキーエラーが発生する場合

- OpenAI APIキーが正しく設定されているか確認
- `.env`ファイルの場所が正しいか確認