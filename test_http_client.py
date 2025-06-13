#!/usr/bin/env python3
"""
HTTP APIクライアントのテストスクリプト

Usage:
    python test_http_client.py [base_url]
    
Example:
    python test_http_client.py http://localhost:8000
"""

import requests
import json
import sys

def test_server(base_url="http://localhost:8000", auth_token=None):
    """HTTPサーバーの動作をテストします"""
    
    print(f"Testing server at {base_url}")
    
    # 認証ヘッダーの設定
    headers = {"Content-Type": "application/json"}
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"
        print(f"Using authentication token")
    
    # 1. ヘルスチェック
    try:
        response = requests.get(f"{base_url}/")
        print(f"✓ Health check: {response.json()}")
    except Exception as e:
        print(f"✗ Health check failed: {e}")
        return False
    
    # 1.5. 認証状態確認
    try:
        response = requests.get(f"{base_url}/auth/status")
        auth_status = response.json()
        print(f"✓ Auth status: {auth_status}")
        
        if auth_status.get("auth_enabled", True) and not auth_token:
            print("⚠️  Authentication is enabled but no token provided. Some tests may fail.")
    except Exception as e:
        print(f"✗ Auth status check failed: {e}")
    
    # 2. ツール一覧の取得
    try:
        response = requests.get(f"{base_url}/tools")
        tools = response.json()
        print(f"✓ Tools available: {len(tools['tools'])} tools")
    except Exception as e:
        print(f"✗ Tools list failed: {e}")
        return False
    
    # 3. 単一脅威のCVSS抽出テスト
    test_threat = "不正なネットワークアクセスにより患者データが漏洩する可能性がある"
    try:
        response = requests.post(
            f"{base_url}/extract_cvss",
            json={"threat_description": test_threat},
            headers=headers
        )
        if response.status_code == 200:
            result = response.json()
            print(f"✓ CVSS extraction: Score {result.get('cvss_metrics', {}).get('score', 'N/A')}")
        elif response.status_code == 401:
            print(f"✗ CVSS extraction failed: Authentication required")
        else:
            print(f"✗ CVSS extraction failed: {response.status_code}")
    except Exception as e:
        print(f"✗ CVSS extraction error: {e}")
    
    # 4. バッチ処理テスト
    test_threats = [
        "医療機器への物理的アクセスにより設定が変更される",
        "ネットワーク経由で診断データが改ざんされる"
    ]
    try:
        response = requests.post(
            f"{base_url}/extract_cvss_batch",
            json={"threat_descriptions": test_threats},
            headers=headers
        )
        if response.status_code == 200:
            result = response.json()
            print(f"✓ Batch processing: {result['statistics']['total']} threats processed")
        elif response.status_code == 401:
            print(f"✗ Batch processing failed: Authentication required")
        else:
            print(f"✗ Batch processing failed: {response.status_code}")
    except Exception as e:
        print(f"✗ Batch processing error: {e}")
    
    # 5. データタイプ抽出テスト
    test_text = "患者の診断画像とバイタルデータが保存されている"
    try:
        response = requests.post(
            f"{base_url}/extract_data_types",
            json={"text": test_text},
            headers=headers
        )
        if response.status_code == 200:
            result = response.json()
            data_types = result.get('extracted_data_types', [])
            print(f"✓ Data types extraction: {len(data_types)} types found")
        elif response.status_code == 401:
            print(f"✗ Data types extraction failed: Authentication required")
        else:
            print(f"✗ Data types extraction failed: {response.status_code}")
    except Exception as e:
        print(f"✗ Data types extraction error: {e}")
    
    # 6. 正規化テスト
    try:
        response = requests.post(
            f"{base_url}/normalize_features",
            json={
                "attack_vector": "ネットワーク経由",
                "data_types": ["患者データ"],
                "impact_types": ["データ漏洩"]
            },
            headers=headers
        )
        if response.status_code == 200:
            result = response.json()
            print(f"✓ Feature normalization: {len(result)} categories normalized")
        elif response.status_code == 401:
            print(f"✗ Feature normalization failed: Authentication required")
        else:
            print(f"✗ Feature normalization failed: {response.status_code}")
    except Exception as e:
        print(f"✗ Feature normalization error: {e}")
    
    print("\nAll tests completed!")
    return True

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Test MCP Threat Extraction HTTP API")
    parser.add_argument("--url", default="http://localhost:8000", help="Base URL of the server")
    parser.add_argument("--token", help="Firebase ID token for authentication")
    
    args = parser.parse_args()
    
    # レガシー引数サポート
    if len(sys.argv) == 2 and not args.token:
        base_url = sys.argv[1]
        auth_token = None
    else:
        base_url = args.url
        auth_token = args.token
    
    test_server(base_url, auth_token)