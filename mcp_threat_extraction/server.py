#!/usr/bin/env python3
"""
MCP Server for Threat Extraction
医療機器の脅威記述文からCVSSスコアとセキュリティ特徴を抽出するMCPサーバー
"""

import sys
import os
import json
import asyncio
from typing import Dict, List, Any
from pathlib import Path

from mcp.server import Server
from mcp.types import Tool, TextContent
from .threat_extraction import calculate_cvss_with_ai, process_threats_with_cvss
from dotenv import load_dotenv
from .logging_config import get_logger

# セマンティック正規化器のインポート
from .semantic_normalizer_optimized import OptimizedSemanticNormalizer

# 環境変数を読み込む
load_dotenv()

# Logger設定
logger = get_logger(__name__)

# MCPサーバーのインスタンスを作成
server = Server("threat-extraction")

# セマンティック正規化器のインスタンス（グローバル）
semantic_normalizer = None

def get_semantic_normalizer():
    """SemanticNormalizerのレイジーローディング"""
    global semantic_normalizer
    if semantic_normalizer is None:
        try:
            import time
            start_time = time.time()
            semantic_normalizer = OptimizedSemanticNormalizer()
            init_time = time.time() - start_time
            logger.info(f"Semantic normalizer initialized in {init_time:.2f} seconds")
        except ImportError as e:
            raise Exception(f"Missing required dependency: {str(e)}. Please install sentence-transformers: pip install sentence-transformers")
        except Exception as e:
            raise Exception(f"Failed to initialize normalizer: {str(e)}")
    return semantic_normalizer

# ツールを定義
@server.list_tools()
async def list_tools() -> List[Tool]:
    """利用可能なツールのリストを返す"""
    return [
        Tool(
            name="extract_cvss",
            description="医療機器の脅威記述文からCVSSスコアとセキュリティ特徴を抽出します",
            inputSchema={
                "type": "object",
                "properties": {
                    "threat_description": {
                        "type": "string",
                        "description": "脅威の記述文（日本語）"
                    }
                },
                "required": ["threat_description"]
            }
        ),
        Tool(
            name="extract_cvss_batch",
            description="複数の脅威記述文からCVSSスコアとセキュリティ特徴をバッチで抽出します",
            inputSchema={
                "type": "object",
                "properties": {
                    "threat_descriptions": {
                        "type": "array",
                        "items": {
                            "type": "string"
                        },
                        "description": "脅威記述文のリスト（日本語）"
                    }
                },
                "required": ["threat_descriptions"]
            }
        ),
        Tool(
            name="extract_data_types",
            description="脅威記述文から影響を受けるデータタイプを抽出します",
            inputSchema={
                "type": "object",
                "properties": {
                    "text": {
                        "type": "string",
                        "description": "データタイプを抽出する対象のテキスト（日本語）"
                    }
                },
                "required": ["text"]
            }
        ),
        Tool(
            name="normalize_features",
            description="セキュリティ特徴を正規化します（攻撃ベクトル、データタイプ、影響タイプ）",
            inputSchema={
                "type": "object",
                "properties": {
                    "attack_vector": {
                        "type": "string",
                        "description": "正規化する攻撃ベクトル"
                    },
                    "data_types": {
                        "type": "array",
                        "items": {
                            "type": "string"
                        },
                        "description": "正規化するデータタイプのリスト"
                    },
                    "impact_types": {
                        "type": "array",
                        "items": {
                            "type": "string"
                        },
                        "description": "正規化する影響タイプのリスト"
                    }
                }
            }
        )
    ]

# ツールハンドラーを定義
@server.call_tool()
async def call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
    """ツール呼び出しを処理する"""
    
    try:
        if name == "extract_cvss":
            # 単一の脅威記述文からCVSSを抽出
            threat_description = arguments.get("threat_description", "")
            if not threat_description:
                return [TextContent(type="text", text="エラー: threat_descriptionが必要です")]
            
            result = calculate_cvss_with_ai(threat_description)
            return [TextContent(type="text", text=json.dumps(result, ensure_ascii=False, indent=2))]
        
        elif name == "extract_cvss_batch":
            # 複数の脅威記述文からCVSSをバッチ抽出
            threat_descriptions = arguments.get("threat_descriptions", [])
            if not threat_descriptions:
                return [TextContent(type="text", text="エラー: threat_descriptionsが必要です")]
            
            results = process_threats_with_cvss(threat_descriptions)
            
            # 統計情報を追加
            severities = {}
            for result in results:
                if "cvss_metrics" in result:
                    severity = result["cvss_metrics"]["severity"]
                    severities[severity] = severities.get(severity, 0) + 1
            
            response = {
                "results": results,
                "statistics": {
                    "total": len(results),
                    "severity_distribution": severities
                }
            }
            
            return [TextContent(type="text", text=json.dumps(response, ensure_ascii=False, indent=2))]
        
        elif name == "extract_data_types":
            # テキストからデータタイプを抽出
            text = arguments.get("text", "")
            if not text:
                return [TextContent(type="text", text="エラー: textが必要です")]
            
            try:
                # 初期化ステータスを返す
                init_response = {
                    "text": text,
                    "status": "initializing_normalizer"
                }
                
                normalizer = get_semantic_normalizer()
                
                # 処理開始ステータス
                processing_status = {
                    "text": text,
                    "status": "processing"
                }
                
                data_types = normalizer.extract_data_types_from_text(text)
                
                response = {
                    "text": text,
                    "extracted_data_types": data_types,
                    "status": "success"
                }
                
                return [TextContent(type="text", text=json.dumps(response, ensure_ascii=False, indent=2))]
            except Exception as normalize_error:
                error_response = {
                    "text": text,
                    "error": f"Normalization error: {str(normalize_error)}",
                    "error_type": type(normalize_error).__name__,
                    "status": "error"
                }
                return [TextContent(type="text", text=json.dumps(error_response, ensure_ascii=False, indent=2))]
        
        elif name == "normalize_features":
            # セキュリティ特徴を正規化
            normalizer = get_semantic_normalizer()
            
            response = {}
            
            # 攻撃ベクトルの正規化
            if "attack_vector" in arguments:
                attack_vector = arguments["attack_vector"]
                normalized_av = normalizer.normalize_attack_vector(attack_vector)
                response["attack_vector"] = {
                    "original": attack_vector,
                    "normalized": normalized_av
                }
            
            # データタイプの正規化
            if "data_types" in arguments:
                data_types = arguments["data_types"]
                normalized_dt = normalizer.normalize_data_types(data_types)
                response["data_types"] = {
                    "original": data_types,
                    "normalized": normalized_dt
                }
            
            # 影響タイプの正規化
            if "impact_types" in arguments:
                impact_types = arguments["impact_types"]
                normalized_it = normalizer.normalize_impact_types(impact_types)
                response["impact_types"] = {
                    "original": impact_types,
                    "normalized": normalized_it
                }
            
            return [TextContent(type="text", text=json.dumps(response, ensure_ascii=False, indent=2))]
        
        else:
            return [TextContent(type="text", text=f"エラー: 不明なツール '{name}'")]
    
    except Exception as e:
        return [TextContent(type="text", text=f"エラー: {str(e)}")]

# HTTP サーバー用の追加インポート
from fastapi import FastAPI, HTTPException, Depends
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from pydantic import BaseModel
from typing import Optional
from .auth import initialize_firebase, require_auth, get_current_user

# HTTPサーバー用のPydanticモデル
class ThreatRequest(BaseModel):
    threat_description: str

class BatchThreatRequest(BaseModel):
    threat_descriptions: List[str]

class DataTypesRequest(BaseModel):
    text: str

class NormalizeRequest(BaseModel):
    attack_vector: Optional[str] = None
    data_types: Optional[List[str]] = None
    impact_types: Optional[List[str]] = None

# Firebase初期化
from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    """アプリケーションのライフサイクル管理"""
    # 起動時の処理
    try:
        initialize_firebase()
    except Exception as e:
        logger.warning(f"Firebase initialization warning: {e}")
    
    yield
    
    # 終了時の処理（必要に応じて）
    pass

# FastAPIアプリケーション
app = FastAPI(
    title="MCP Threat Extraction Server",
    description="医療機器の脅威記述文からCVSSスコアとセキュリティ特徴を抽出するHTTPサーバー",
    version="0.3.0",
    lifespan=lifespan
)

# CORS設定
# デフォルトのローカル開発用オリジン
default_origins = [
    "http://localhost:3000",
    "http://localhost:3001",
    "http://localhost:5173",
    "http://localhost:8080",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:3001",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:8080",
]

# 環境変数から追加のオリジンを取得
env_origins = os.getenv("ALLOWED_ORIGINS", "")
if env_origins == "*":
    # ワイルドカードが指定された場合はそのまま使用
    allowed_origins = ["*"]
else:
    # 環境変数のオリジンをパース
    additional_origins = [origin.strip() for origin in env_origins.split(",") if origin.strip()]
    # デフォルトと環境変数のオリジンを結合
    allowed_origins = default_origins + additional_origins
    # 重複を削除
    allowed_origins = list(dict.fromkeys(allowed_origins))

logger.info(f"CORS allowed origins: {allowed_origins}")

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
@app.head("/")
async def root():
    """ルートエンドポイント"""
    return {"message": "MCP Threat Extraction Server", "version": "0.3.0"}

@app.get("/tools")
async def get_tools():
    """利用可能なツールのリストを返す"""
    tools = await list_tools()
    return {"tools": [tool.model_dump() for tool in tools]}

# 認証関連のエンドポイント
@app.get("/auth/me")
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    """現在のユーザー情報を取得"""
    return {"user": current_user}

@app.get("/auth/status")
async def auth_status():
    """認証設定の状態を確認"""
    auth_disabled = os.getenv("DISABLE_AUTH", "false").lower() == "true"
    return {
        "auth_enabled": not auth_disabled,
        "auth_method": "firebase" if not auth_disabled else "disabled"
    }


@app.post("/extract_cvss")
async def extract_cvss_endpoint(request: ThreatRequest, current_user: dict = Depends(require_auth)):
    """単一の脅威記述文からCVSSスコアを抽出"""
    try:
        result = await call_tool("extract_cvss", {"threat_description": request.threat_description})
        response_data = json.loads(result[0].text)
        response_data["user"] = current_user["uid"]
        return JSONResponse(content=response_data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/extract_cvss_batch")
async def extract_cvss_batch_endpoint(request: BatchThreatRequest, current_user: dict = Depends(require_auth)):
    """複数の脅威記述文からCVSSスコアをバッチ抽出"""
    try:
        result = await call_tool("extract_cvss_batch", {"threat_descriptions": request.threat_descriptions})
        response_data = json.loads(result[0].text)
        response_data["user"] = current_user["uid"]
        return JSONResponse(content=response_data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/extract_data_types")
async def extract_data_types_endpoint(request: DataTypesRequest, current_user: dict = Depends(require_auth)):
    """テキストからデータタイプを抽出"""
    try:
        result = await call_tool("extract_data_types", {"text": request.text})
        response_data = json.loads(result[0].text)
        response_data["user"] = current_user["uid"]
        return JSONResponse(content=response_data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/normalize_features")
async def normalize_features_endpoint(request: NormalizeRequest, current_user: dict = Depends(require_auth)):
    """セキュリティ特徴を正規化"""
    try:
        arguments = {}
        if request.attack_vector:
            arguments["attack_vector"] = request.attack_vector
        if request.data_types:
            arguments["data_types"] = request.data_types
        if request.impact_types:
            arguments["impact_types"] = request.impact_types
        
        result = await call_tool("normalize_features", arguments)
        response_data = json.loads(result[0].text)
        response_data["user"] = current_user["uid"]
        return JSONResponse(content=response_data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# メイン実行
async def main():
    """サーバーを起動する"""
    from mcp.server.stdio import stdio_server
    
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options()
        )

async def run_http_server(host: str = "0.0.0.0", port: int = 8000):
    """HTTPサーバーを起動する"""
    config = uvicorn.Config(app, host=host, port=port, log_level="info")
    server = uvicorn.Server(config)
    await server.serve()

def create_server():
    """Create and return the MCP server instance"""
    return server

if __name__ == "__main__":
    asyncio.run(main())