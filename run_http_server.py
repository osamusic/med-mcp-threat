#!/usr/bin/env python3
"""
HTTP サーバー起動スクリプト
独立したHTTPサーバーとしてMCP Threat Extraction Serverを起動します
"""

import asyncio
import argparse
import os
from mcp_threat_extraction.server import run_http_server

def main():
    parser = argparse.ArgumentParser(description="MCP Threat Extraction HTTP Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind to (default: 8000)")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload for development")
    
    args = parser.parse_args()
    
    print(f"Starting MCP Threat Extraction HTTP Server on {args.host}:{args.port}")
    
    if args.reload:
        # 開発モード用の自動リロード
        import uvicorn
        uvicorn.run(
            "mcp_threat_extraction.server:app",
            host=args.host,
            port=args.port,
            reload=True,
            log_level="info"
        )
    else:
        # プロダクション用
        asyncio.run(run_http_server(host=args.host, port=args.port))

if __name__ == "__main__":
    main()