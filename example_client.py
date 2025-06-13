#!/usr/bin/env python3
"""
MCP Threat Extraction Client Example
MCPサーバーを使用する例
"""

import asyncio
import json
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def main():
    # MCPサーバーのパラメータ
    server_params = StdioServerParameters(
        command="mcp-threat-extraction"
    )
    
    # クライアントセッションを開始
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            # サーバーを初期化
            await session.initialize()
            
            # 利用可能なツールを確認
            tools = await session.list_tools()
            print("利用可能なツール:")
            for tool in tools:
                print(f"  - {tool.name}: {tool.description}")
            
            # 1. 単一の脅威を分析
            print("\n--- 単一の脅威分析 ---")
            result = await session.call_tool(
                "extract_cvss",
                {
                    "threat_description": "攻撃者がUSBメモリを介して輸液ポンプにマルウェアを仕込み、不正操作を可能にした。"
                }
            )
            print(json.dumps(json.loads(result[0].text), indent=2, ensure_ascii=False))
            
            # 2. データタイプ抽出
            print("\n--- データタイプ抽出 ---")
            result = await session.call_tool(
                "extract_data_types",
                {
                    "text": "患者の個人医療情報と診断画像が漏洩した"
                }
            )
            print(json.dumps(json.loads(result[0].text), indent=2, ensure_ascii=False))
            
            # 3. バッチ処理
            print("\n--- バッチ処理 ---")
            result = await session.call_tool(
                "extract_cvss_batch",
                {
                    "threat_descriptions": [
                        "外部ネットワークからAPIに未認証アクセスされ、患者データが漏洩した。",
                        "手術ロボットのファームウェアを改ざんすることで、手術中の誤動作を引き起こした。"
                    ]
                }
            )
            batch_result = json.loads(result[0].text)
            print(f"処理件数: {batch_result['statistics']['total']}")
            print(f"重要度分布: {batch_result['statistics']['severity_distribution']}")

if __name__ == "__main__":
    asyncio.run(main())