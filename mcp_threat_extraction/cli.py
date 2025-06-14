#!/usr/bin/env python3
"""
CLI entry point for MCP Threat Extraction Server
"""

import asyncio
import sys
from .server import main as server_main
from .logging_config import get_logger

# Logger設定
logger = get_logger(__name__)

def main():
    """CLI entry point"""
    try:
        asyncio.run(server_main())
    except KeyboardInterrupt:
        logger.info("サーバーを停止しました。")
        sys.exit(0)
    except Exception as e:
        logger.error(f"エラー: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()