#!/usr/bin/env python3
"""
MCP Server Test Script
サーバーの基本的な機能をテストします
"""

import sys
import os
from pathlib import Path

# プロジェクトのルートディレクトリをPythonパスに追加
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

def test_imports():
    """必要なモジュールがインポートできるかテスト"""
    print("🧪 インポートテスト...")
    try:
        from threat_extraction import calculate_cvss_with_ai
        print("✅ threat_extraction モジュール: OK")
    except Exception as e:
        print(f"❌ threat_extraction モジュール: {e}")
        return False
    
    try:
        from semantic_normalizer_optimized import OptimizedSemanticNormalizer
        print("✅ semantic_normalizer_optimized モジュール: OK")
    except Exception as e:
        print(f"❌ semantic_normalizer_optimized モジュール: {e}")
        return False
    
    try:
        from cvss_logic import CVSSLogicEngine
        print("✅ cvss_logic モジュール: OK")
    except Exception as e:
        print(f"❌ cvss_logic モジュール: {e}")
        return False
    
    return True

def test_semantic_normalizer():
    """セマンティック正規化器のテスト"""
    print("\n🧪 セマンティック正規化器テスト...")
    try:
        from semantic_normalizer_optimized import OptimizedSemanticNormalizer
        normalizer = OptimizedSemanticNormalizer()
        
        # データタイプ抽出テスト
        test_text = "患者の個人医療情報が漏洩した"
        data_types = normalizer.extract_data_types_from_text(test_text)
        print(f"✅ データタイプ抽出: {data_types}")
        
        # 攻撃ベクトル正規化テスト
        av = normalizer.normalize_attack_vector("ネットワーク経由")
        print(f"✅ 攻撃ベクトル正規化: 'ネットワーク経由' → '{av}'")
        
        return True
    except Exception as e:
        print(f"❌ エラー: {e}")
        return False

def test_cvss_extraction():
    """CVSS抽出機能のテスト（OpenAI API必要）"""
    print("\n🧪 CVSS抽出テスト...")
    
    # OpenAI APIキーの確認
    if not os.getenv("OPENAI_API_KEY"):
        print("⚠️  OPENAI_API_KEY が設定されていません。スキップします。")
        return True
    
    try:
        from threat_extraction import calculate_cvss_with_ai
        
        test_threat = "攻撃者がUSBメモリを介して輸液ポンプにマルウェアを仕込み、不正操作を可能にした。"
        print(f"テスト脅威: {test_threat}")
        
        result = calculate_cvss_with_ai(test_threat)
        
        print(f"✅ CVSS抽出成功:")
        print(f"  - ベーススコア: {result['cvss_metrics']['base_score']}")
        print(f"  - 重要度: {result['cvss_metrics']['severity']}")
        print(f"  - 攻撃ベクトル: {result['cvss_metrics']['attack_vector']}")
        
        return True
    except Exception as e:
        print(f"❌ エラー: {e}")
        return False

def main():
    """メインテスト実行"""
    print("MCP Threat Extraction Server テスト\n")
    
    all_passed = True
    
    # インポートテスト
    if not test_imports():
        all_passed = False
    
    # セマンティック正規化器テスト
    if not test_semantic_normalizer():
        all_passed = False
    
    # CVSS抽出テスト
    if not test_cvss_extraction():
        all_passed = False
    
    print("\n" + "="*50)
    if all_passed:
        print("✅ すべてのテストが成功しました！")
        print("\nMCPサーバーを起動するには:")
        print("  cd mcp-threat-extraction")
        print("  uv run python server.py")
    else:
        print("❌ 一部のテストが失敗しました。")
    
    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(main())