#!/usr/bin/env python3
"""
CLI entry point for MCP Threat Extraction Server
"""

import asyncio
import sys
from .server import main as server_main

def main():
    """CLI entry point"""
    try:
        asyncio.run(server_main())
    except KeyboardInterrupt:
        print("\nサーバーを停止しました。")
        sys.exit(0)
    except Exception as e:
        print(f"エラー: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()