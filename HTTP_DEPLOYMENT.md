# HTTP サーバーとしてのデプロイ手順

このMCPサーバーを独立したHTTPサーバーとして起動・デプロイする方法について説明します。

## 概要

従来のClaude Desktop用のstdio MCPサーバーに加えて、独立したHTTPサーバーとしても動作するように拡張されました。

## ローカル起動

### 1. 直接起動
```bash
# 基本起動
python run_http_server.py

# ホスト・ポート指定
python run_http_server.py --host 0.0.0.0 --port 8080

# 開発モード（自動リロード）
python run_http_server.py --reload
```

### 2. パッケージ経由で起動（インストール後）
```bash
pip install -e .
mcp-threat-http-server --port 8080
```

## Docker デプロイ

### 1. Docker Compose使用
```bash
# 環境変数設定
cp .env.example .env
# .envファイルにAPIキーを設定

# 起動
docker-compose up -d

# ログ確認
docker-compose logs -f

# 停止
docker-compose down
```

### 2. Docker直接使用
```bash
# ビルド
docker build -t mcp-threat-extraction .

# 起動
docker run -d \
  -p 8000:8000 \
  -e OPENAI_API_KEY=your_key \
  -e ANTHROPIC_API_KEY=your_key \
  --name mcp-threat-server \
  mcp-threat-extraction
```

## API エンドポイント

### ベースURL
- ローカル: `http://localhost:8000`
- Docker: `http://localhost:8000`

### エンドポイント一覧

#### 1. ヘルスチェック
```
GET /
```

#### 2. 利用可能ツール一覧
```
GET /tools
```

#### 3. CVSS抽出（単一）
```
POST /extract_cvss
Content-Type: application/json

{
  "threat_description": "医療機器への不正アクセスによりデータが漏洩する"
}
```

#### 4. CVSS抽出（バッチ）
```
POST /extract_cvss_batch
Content-Type: application/json

{
  "threat_descriptions": [
    "脅威の説明1",
    "脅威の説明2"
  ]
}
```

#### 5. データタイプ抽出
```
POST /extract_data_types
Content-Type: application/json

{
  "text": "患者の診断データと画像が保存されている"
}
```

#### 6. 特徴正規化
```
POST /normalize_features
Content-Type: application/json

{
  "attack_vector": "ネットワーク経由",
  "data_types": ["患者データ"],
  "impact_types": ["データ漏洩"]
}
```

## テスト

### APIテスト実行
```bash
# サーバー起動後
python test_http_client.py

# 別のURLでテスト
python test_http_client.py http://your-server:8000
```

### curlでのテスト例
```bash
# ヘルスチェック
curl http://localhost:8000/

# CVSS抽出
curl -X POST http://localhost:8000/extract_cvss \
  -H "Content-Type: application/json" \
  -d '{"threat_description": "不正アクセスによるデータ漏洩"}'
```

## プロダクション環境での注意点

1. **環境変数の設定**
   - `OPENAI_API_KEY` または `ANTHROPIC_API_KEY` が必要
   - `.env` ファイルまたは環境変数で設定

2. **セキュリティ**
   - APIキーを安全に管理
   - 必要に応じてHTTPS/認証の追加を検討

3. **パフォーマンス**
   - セマンティック正規化器の初期化に時間がかかる場合があります
   - 初回リクエスト時にモデルがダウンロードされます

4. **スケーリング**
   - 複数インスタンスでの実行に対応
   - ロードバランサーと組み合わせて使用可能

## トラブルシューティング

### よくある問題

1. **依存関係エラー**
   ```bash
   pip install -r requirements.txt
   ```

2. **モデルダウンロードエラー**
   - インターネット接続を確認
   - 十分なディスク容量があることを確認

3. **ポート衝突**
   - 別のポート番号を指定: `--port 8080`

4. **メモリ不足**
   - セマンティック正規化に多くのメモリが必要な場合があります
   - Dockerの場合はメモリ制限を調整

## MCP vs HTTP の選択

- **MCP (stdio)**: Claude Desktopとの直接統合用
- **HTTP**: 独立したAPIサーバー、他のアプリケーションからの利用用

両方の形式に対応しているため、用途に応じて選択できます。