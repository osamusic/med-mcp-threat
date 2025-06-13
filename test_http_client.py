#!/usr/bin/env python3
"""
HTTP APIクライアントのテストスクリプト
"""

import requests
import json
import sys

def test_server(base_url="http://localhost:8000"):
    """HTTPサーバーの動作をテストします"""
    
    print(f"Testing server at {base_url}")
    
    # 1. ヘルスチェック
    try:
        response = requests.get(f"{base_url}/")
        print(f"✓ Health check: {response.json()}")
    except Exception as e:
        print(f"✗ Health check failed: {e}")
        return False
    
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
            json={"threat_description": test_threat}
        )
        if response.status_code == 200:
            result = response.json()
            print(f"✓ CVSS extraction: Score {result.get('cvss_metrics', {}).get('score', 'N/A')}")
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
            json={"threat_descriptions": test_threats}
        )
        if response.status_code == 200:
            result = response.json()
            print(f"✓ Batch processing: {result['statistics']['total']} threats processed")
        else:
            print(f"✗ Batch processing failed: {response.status_code}")
    except Exception as e:
        print(f"✗ Batch processing error: {e}")
    
    # 5. データタイプ抽出テスト
    test_text = "患者の診断画像とバイタルデータが保存されている"
    try:
        response = requests.post(
            f"{base_url}/extract_data_types",
            json={"text": test_text}
        )
        if response.status_code == 200:
            result = response.json()
            data_types = result.get('extracted_data_types', [])
            print(f"✓ Data types extraction: {len(data_types)} types found")
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
            }
        )
        if response.status_code == 200:
            result = response.json()
            print(f"✓ Feature normalization: {len(result)} categories normalized")
        else:
            print(f"✗ Feature normalization failed: {response.status_code}")
    except Exception as e:
        print(f"✗ Feature normalization error: {e}")
    
    print("\nAll tests completed!")
    return True

if __name__ == "__main__":
    base_url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
    test_server(base_url)