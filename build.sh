#!/bin/bash
# Build script for MCP Threat Extraction package

echo "🏗️  MCP Threat Extraction パッケージのビルドを開始します..."

# スクリプトのディレクトリを取得
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# クリーンアップ
echo "📦 既存のビルドディレクトリをクリーンアップ..."
rm -rf "$SCRIPT_DIR/build/" "$SCRIPT_DIR/dist/" "$SCRIPT_DIR"/*.egg-info/

# ビルド
echo "🔨 パッケージをビルド中..."
cd "$PROJECT_ROOT" && uv run python -m build mcp-threat-extraction/

# 確認
if [ -d "$SCRIPT_DIR/dist" ]; then
    echo "✅ ビルドが完了しました！"
    echo "📦 生成されたファイル:"
    ls -la "$SCRIPT_DIR/dist/"
else
    echo "❌ ビルドに失敗しました。"
    exit 1
fi

echo ""
echo "📝 インストール方法:"
echo "  pip install dist/mcp_threat_extraction-*.whl"
echo ""
echo "🚀 使用方法:"
echo "  mcp-threat-extraction  # コマンドラインから実行"
echo ""
echo "  またはClaude Desktopの設定に追加:"
echo '  {
    "mcpServers": {
      "threat-extraction": {
        "command": "mcp-threat-extraction"
      }
    }
  }'