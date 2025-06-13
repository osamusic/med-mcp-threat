# HTTP サーバーとしてのデプロイ手順

このMCPサーバーを独立したHTTPサーバーとして起動・デプロイする方法について説明します。

## 概要

従来のClaude Desktop用のstdio MCPサーバーに加えて、独立したHTTPサーバーとしても動作するように拡張されました。

## ローカル起動

### 1. uvicornで直接起動
```bash
# 基本起動
uvicorn mcp_threat_extraction.server:app

# ホスト・ポート指定
uvicorn mcp_threat_extraction.server:app --host 0.0.0.0 --port 8080

# 開発モード（自動リロード）
uvicorn mcp_threat_extraction.server:app --reload
```

### 2. 本番環境での起動
```bash
# ワーカー数指定
uvicorn mcp_threat_extraction.server:app --host 0.0.0.0 --port 8000 --workers 4

# アクセスログ有効
uvicorn mcp_threat_extraction.server:app --host 0.0.0.0 --port 8000 --access-log
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
# ビルド（CPU版）
docker build -t mcp-threat-extraction .

# 起動
docker run -d \
  -p 8000:8000 \
  -e OPENAI_API_KEY=your_key \
  -e ANTHROPIC_API_KEY=your_key \
  --name mcp-threat-server \
  mcp-threat-extraction
```

**注意**: DockerイメージはCPU専用版のPyTorchを使用してNVIDIA/CUDAの依存関係を排除しています（`pyproject.toml`の`[tool.uv]`設定により自動的にCPU版を選択）。

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
# サーバー起動
uvicorn mcp_threat_extraction.server:app &

# テスト実行
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

## Firebase認証の設定

### 1. Firebaseプロジェクトの設定
```bash
# Firebase CLIのインストール
npm install -g firebase-tools

# Firebaseプロジェクトの作成
firebase init

# サービスアカウントキーの生成
# Firebase Console > プロジェクト設定 > サービス アカウント > 新しい秘密鍵の生成
```

### 2. 環境変数の設定
```bash
# .envファイルを作成
cp .env.example .env

# Firebase設定（以下のいずれかの方法で設定）

# 方法1: サービスアカウントキーファイルのパス
FIREBASE_SERVICE_ACCOUNT_KEY=/path/to/firebase-service-account.json

# 方法2: JSON文字列として設定
FIREBASE_SERVICE_ACCOUNT_KEY='{"type":"service_account","project_id":"...","private_key_id":"..."}'

# 方法3: 個別の環境変数として設定（CI/CDやクラウド環境推奨）
FIREBASE_PROJECT_ID=your-project-id
FIREBASE_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"
FIREBASE_CLIENT_EMAIL=firebase-adminsdk-xxxxx@your-project-id.iam.gserviceaccount.com
FIREBASE_CLIENT_ID=1234567890
```

### 3. 認証が必要なエンドポイント
- `POST /extract_cvss` - CVSS抽出
- `POST /extract_cvss_batch` - バッチCVSS抽出  
- `POST /extract_data_types` - データタイプ抽出
- `POST /normalize_features` - 特徴正規化
- `GET /auth/me` - ユーザー情報取得

### 4. 認証が不要なエンドポイント
- `GET /` - ヘルスチェック
- `GET /tools` - ツール一覧
- `GET /auth/status` - 認証状態確認

### 5. 開発環境での認証無効化
```bash
# 開発時に認証を無効にする
export DISABLE_AUTH=true
uvicorn mcp_threat_extraction.server:app --reload
```

## API使用例（認証付き）

### 1. Firebaseでユーザー認証を行い、IDトークンを取得

### 2. APIリクエストにトークンを含める
```bash
# Authorization ヘッダーにBearerトークンを設定
curl -X POST http://localhost:8000/extract_cvss \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_FIREBASE_ID_TOKEN" \
  -d '{"threat_description": "脅威の説明"}'
```

## プロダクション環境での注意点

1. **環境変数の設定**
   - `OPENAI_API_KEY` または `ANTHROPIC_API_KEY` が必要
   - `FIREBASE_SERVICE_ACCOUNT_KEY` が必要
   - `.env` ファイルまたは環境変数で設定

2. **セキュリティ**
   - APIキーとFirebaseサービスアカウントキーを安全に管理
   - CORS設定を本番環境に適した値に変更
   - HTTPS通信を使用
   - ユーザー管理はFirebase Consoleで直接実行

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