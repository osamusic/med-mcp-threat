FROM python:3.12-slim

WORKDIR /app

# システムの依存関係をインストール
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Pythonの依存関係をコピーしてインストール
COPY pyproject.toml uv.lock ./
COPY requirements.txt ./

# uvをインストール
RUN pip install uv

# 依存関係をインストール
RUN uv pip install --system -r requirements.txt

# アプリケーションコードをコピー
COPY . .

# アプリケーションをインストール
RUN pip install -e .

# ポート8000を公開
EXPOSE 8000

# ヘルスチェック用にcurlをインストール済み

# HTTPサーバーを起動
CMD ["uvicorn", "mcp_threat_extraction.server:app", "--host", "0.0.0.0", "--port", "8000"]