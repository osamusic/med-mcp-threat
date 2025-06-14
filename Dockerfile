FROM python:3.13-slim

WORKDIR /app

# システムの依存関係をインストール
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# uvをインストール
RUN pip install uv

# Pythonの依存関係をコピーしてインストール
COPY pyproject.toml uv.lock ./

# CPU版の依存関係をインストール（CUDA依存を回避）
RUN uv sync --frozen --no-dev

# アプリケーションコードをコピー
COPY . .

# アプリケーションをインストール
RUN uv pip install --system --no-deps -e .

# ポート8000を公開
EXPOSE 8000

# ヘルスチェック用にcurlをインストール済み

# HTTPサーバーを起動
CMD ["uv", "run", "uvicorn", "mcp_threat_extraction.server:app", "--host", "0.0.0.0", "--port", "8000"]