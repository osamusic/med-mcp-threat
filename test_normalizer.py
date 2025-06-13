#!/usr/bin/env python3
"""
Semantic Normalizer テストスクリプト
extract_data_types機能のデバッグ用
"""

import sys
from pathlib import Path

# パッケージのパスを追加
sys.path.insert(0, str(Path(__file__).parent / "mcp_threat_extraction"))

def test_normalizer():
    """Semantic Normalizerのテスト"""
    try:
        print("🧪 Semantic Normalizer テスト開始...")
        
        # インポートテスト
        print("📦 インポートテスト...")
        from semantic_normalizer_optimized import OptimizedSemanticNormalizer
        print("✅ インポート成功")
        
        # 初期化テスト
        print("🔧 初期化テスト...")
        normalizer = OptimizedSemanticNormalizer()
        print("✅ 初期化成功")
        
        # データタイプ抽出テスト
        print("🔍 データタイプ抽出テスト...")
        test_text = "患者の個人医療情報が漏洩した"
        print(f"テストテキスト: {test_text}")
        
        data_types = normalizer.extract_data_types_from_text(test_text)
        print(f"✅ 抽出結果: {data_types}")
        
        # 複数テストケース
        test_cases = [
            "CTスキャンの医療画像データが改ざんされた",
            "心電図データが外部に送信された", 
            "薬剤投与量の情報が書き換えられた",
            "患者のバイタルサインデータが漏洩した"
        ]
        
        print("\n📊 複数テストケース:")
        for i, test_case in enumerate(test_cases, 1):
            try:
                result = normalizer.extract_data_types_from_text(test_case)
                print(f"  {i}. {test_case}")
                print(f"     → {result}")
            except Exception as e:
                print(f"  {i}. {test_case}")
                print(f"     ❌ エラー: {e}")
        
        print("\n✅ すべてのテストが完了しました！")
        return True
        
    except Exception as e:
        print(f"❌ エラー: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_normalizer()
    sys.exit(0 if success else 1)