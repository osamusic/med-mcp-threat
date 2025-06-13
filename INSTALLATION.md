# MCP Threat Extraction インストールガイド

## パッケージ化完了

MCP Threat Extractionサーバーがパッケージ化されました。

**v1.1.0の重要な更新**: Windows環境でのModuleNotFoundErrorを解決。全ての依存関係がパッケージ内に含まれた自己完結型になりました。

## ディレクトリ構造

```
mcp-threat-extraction/
├── mcp_threat_extraction/      # パッケージ本体
│   ├── __init__.py
│   ├── server.py               # MCPサーバー実装
│   └── cli.py                  # CLIエントリーポイント
├── dist/                       # ビルド済みパッケージ
│   ├── mcp_threat_extraction-1.1.0-py3-none-any.whl  (自己完結型)
│   └── mcp_threat_extraction-1.1.0.tar.gz
├── pyproject.toml              # パッケージ設定
├── build.sh                    # ビルドスクリプト
├── README.md
└── LICENSE
```

## インストール方法

### 1. ローカルインストール（開発用）

```bash
cd mcp-threat-extraction
pip install -e .
```

### 2. Wheelファイルからインストール

```bash
pip install dist/mcp_threat_extraction-1.1.0-py3-none-any.whl
```

### 3. uvでインストール

```bash
uv pip install dist/mcp_threat_extraction-1.1.0-py3-none-any.whl
```

## 使用方法

### コマンドラインから実行

インストール後、以下のコマンドで実行できます：

```bash
mcp-threat-extraction
```

### Claude Desktopでの設定

`~/.config/Claude/claude_desktop_config.json`（または適切な設定ファイル）に追加：

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

### Pythonから直接使用

```python
from mcp_threat_extraction import server
# サーバーインスタンスを取得
mcp_server = server
```

## 依存関係

パッケージは以下の依存関係を自動的にインストールします：

- mcp>=0.1.0
- langchain-openai
- langchain-core
- python-dotenv
- tqdm
- sentence-transformers
- scikit-learn
- numpy
- torch

## 再ビルド

更新後にパッケージを再ビルドする場合：

```bash
cd mcp-threat-extraction
./build.sh
```

## 配布

生成された`.whl`ファイルや`.tar.gz`ファイルを配布することで、他の環境でも簡単にインストールできます。