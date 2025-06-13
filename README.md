# MCP Threat Extraction Server

医療機器の脅威記述文からCVSSスコアとセキュリティ特徴を抽出するMCP (Model Context Protocol) サーバーです。

## 機能

このMCPサーバーは以下のツールを提供します：

### 1. extract_cvss
単一の脅威記述文からCVSSスコアとセキュリティ特徴を抽出します。

**入力:**
- `threat_description` (string): 脅威の記述文（日本語）

**出力:**
- CVSSメトリクス（攻撃ベクトル、複雑度、権限要求等）
- ベーススコアと重要度
- 抽出された特徴
- 決定ロジックのパス

### 2. extract_cvss_batch
複数の脅威記述文をバッチ処理します。

**入力:**
- `threat_descriptions` (array): 脅威記述文のリスト

**出力:**
- 各脅威の分析結果
- 重要度別の統計情報

### 3. extract_data_types
テキストから影響を受けるデータタイプを抽出します。

**入力:**
- `text` (string): 分析対象のテキスト

**出力:**
- 抽出されたデータタイプのリスト（personal_medical、diagnostic_imaging等）

### 4. normalize_features
セキュリティ特徴を正規化します。

**入力:**
- `attack_vector` (string, optional): 攻撃ベクトル
- `data_types` (array, optional): データタイプのリスト
- `impact_types` (array, optional): 影響タイプのリスト

**出力:**
- 正規化された各特徴

## セットアップ

### 前提条件
- Python 3.12以上
- uv (Pythonパッケージマネージャー)
- OpenAI APIキー

### インストール

1. プロジェクトのルートディレクトリで依存関係をインストール:
```bash
uv sync
```

2. 環境変数を設定（プロジェクトルートの`.env`ファイル）:
```
OPENAI_API_KEY=your_api_key
OPENAI_MODEL=gpt-4
```

## 使用方法

### MCPクライアントの設定

Claude Desktopなどのクライアントの設定ファイルに以下を追加:

```json
{
  "mcpServers": {
    "threat-extraction": {
      "command": "uv",
      "args": ["run", "python", "/path/to/threat/mcp-threat-extraction/server.py"],
      "cwd": "/path/to/threat"
    }
  }
}
```

### 使用例

```javascript
// 単一の脅威を分析
const result = await use_mcp_tool("threat-extraction", "extract_cvss", {
  threat_description: "攻撃者がUSBメモリを介して輸液ポンプにマルウェアを仕込み、不正操作を可能にした。"
});

// バッチ処理
const batchResult = await use_mcp_tool("threat-extraction", "extract_cvss_batch", {
  threat_descriptions: [
    "外部ネットワークからAPIに未認証アクセスされ、患者データが漏洩した。",
    "手術ロボットのファームウェアを改ざんすることで、手術中の誤動作を引き起こした。"
  ]
});

// データタイプの抽出
const dataTypes = await use_mcp_tool("threat-extraction", "extract_data_types", {
  text: "患者の個人医療情報と診断画像が漏洩した"
});
```

## 技術仕様

- **CVSS v3.1準拠**: 標準的なCVSSスコアリング方式を採用
- **医療機器特化**: 医療機器の安全性クラスやデータ分類を考慮
- **セマンティック分析**: SentenceTransformerによる高精度な特徴抽出
- **多言語対応**: 日本語の医療用語に特化した辞書を搭載

## トラブルシューティング

### OpenAI APIエラー
- APIキーが正しく設定されているか確認
- APIの利用制限に達していないか確認


### パフォーマンス
- 初回起動時はモデルのロードに時間がかかります
- 2回目以降はレイジーローディングにより高速化されます