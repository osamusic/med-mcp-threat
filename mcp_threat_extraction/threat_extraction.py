from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser
from langchain_core.runnables import RunnableLambda
import os
import json
from pprint import pprint
from dotenv import load_dotenv
from tqdm import tqdm
from typing import Dict, Tuple
from dataclasses import dataclass
from .threat_data import (
    DEVICE_TYPES, THREAT_TEMPLATES, COUNTERMEASURES_DB,
    ASSET_CLASSIFICATION, DATA_CLASSIFICATION, CVSS_ATTACK_PATTERNS,
    ATTACK_VECTORS, ATTACK_COMPLEXITY, PRIVILEGES_REQUIRED,
    USER_INTERACTION, SCOPE, IMPACT_LEVELS, SEVERITY_RATINGS
)
from .cvss_logic import CVSSMetrics, CVSSCalculator, CVSSLogicEngine

# セマンティック正規化器のインポート
from .semantic_normalizer_optimized import OptimizedSemanticNormalizer

# 最適化されたSemanticNormalizerのインスタンス（レイジーローディング）
semantic_normalizer = None

def get_semantic_normalizer():
    """SemanticNormalizerのレイジーローディング"""
    global semantic_normalizer
    if semantic_normalizer is None:
        semantic_normalizer = OptimizedSemanticNormalizer()
    return semantic_normalizer

def normalize_features_with_semantic(raw: dict) -> dict:
    """最適化されたSemanticNormalizerを使用した特徴の正規化"""
    
    normalizer = get_semantic_normalizer()
    
    # 攻撃ベクトルの正規化
    attack_vector_raw = raw.get("attack_vector", "")
    if isinstance(attack_vector_raw, list):
        attack_vector_raw = attack_vector_raw[0] if attack_vector_raw else ""
    attack_vector = normalizer.normalize_attack_vector(str(attack_vector_raw))
    
    # データタイプの正規化
    data_type_raw = raw.get("data_type", [])
    if not isinstance(data_type_raw, list):
        data_type_raw = [data_type_raw] if data_type_raw else []
    data_types = normalizer.normalize_data_types(data_type_raw)
    
    # 影響タイプの正規化
    impact_type_raw = raw.get("impact_type", [])
    if not isinstance(impact_type_raw, list):
        impact_type_raw = [impact_type_raw] if impact_type_raw else []
    impact_types = normalizer.normalize_impact_types(impact_type_raw)
    
    return {
        "attack_vector": attack_vector,
        "device_type": raw.get("device_type", ""),
        "attack_type": raw.get("attack_type", ""),
        "requires_authentication": raw.get("requires_authentication", False),
        "requires_user_interaction": raw.get("requires_user_interaction", False),
        "asset_category": raw.get("asset_category", ""),
        "data_type": data_types,
        "impact_type": impact_types
    }

def extract_data_type_from_description(threat_description: str) -> list:
    """脅威記述文から直接データタイプを推定（最適化されたSemanticNormalizer使用）"""
    normalizer = get_semantic_normalizer()
    return normalizer.extract_data_types_from_text(threat_description)

def determine_cvss_from_features(features: dict, threat_description: str) -> CVSSMetrics:
    """AIで抽出した特徴からCVSSメトリクスを決定（完全に共通モジュールを使用）"""
    
    logic_paths = {}
    
    # CVSSロジックエンジンを初期化
    cvss_logic = CVSSLogicEngine(ASSET_CLASSIFICATION, DATA_CLASSIFICATION, CVSS_ATTACK_PATTERNS)
    
    # データタイプの補完: AIが抽出できなかった場合は脅威記述文から推定
    if not features.get("data_type"):
        features["data_type"] = extract_data_type_from_description(threat_description)
    
    # 攻撃カテゴリを特徴から推定
    threat_category = "ソフトウェア"  # デフォルト
    if features.get("attack_vector") == "network":
        threat_category = "ネットワーク"
    elif features.get("attack_vector") == "physical":
        threat_category = "物理"
    elif features.get("attack_vector") == "wireless":
        threat_category = "無線"
    
    # 攻撃ベクトルの決定（共通モジュール）
    av, av_path = cvss_logic.determine_attack_vector_with_path(
        threat_category,
        threat_description, 
        features.get("device_type", ""),
        "extraction"
    )
    logic_paths["attack_vector"] = av_path
    
    # 攻撃複雑度の決定（共通モジュール）
    ac, ac_path = cvss_logic.determine_attack_complexity_with_path(
        threat_description, 
        features.get("device_type", "")
    )
    logic_paths["attack_complexity"] = ac_path
    
    # 必要権限の決定（共通モジュール）
    pr, pr_path = cvss_logic.determine_privileges_required_with_path(
        threat_description,
        threat_category,
        features.get("requires_authentication", False)
    )
    logic_paths["privileges_required"] = pr_path
    
    # ユーザー操作の必要性（共通モジュール）
    ui, ui_path = cvss_logic.determine_user_interaction_with_path(
        threat_description,
        features.get("requires_user_interaction", False)
    )
    logic_paths["user_interaction"] = ui_path
    
    # スコープの決定（共通モジュール）
    scope, scope_path = cvss_logic.determine_scope_with_path(
        threat_description, 
        features.get("device_type", "")
    )
    logic_paths["scope"] = scope_path
    
    # CIA影響度の決定（共通モジュール）
    c, i, a, cia_path = cvss_logic.determine_cia_impact_with_path(
        threat_description, 
        features.get("device_type", ""),
        features.get("impact_type", []),
        features.get("data_type", []),
        features.get("attack_type", "")
    )
    logic_paths["cia_impact"] = cia_path
    
    return CVSSMetrics(
        attack_vector=av,
        attack_complexity=ac,
        privileges_required=pr,
        user_interaction=ui,
        scope=scope,
        confidentiality=c,
        integrity=i,
        availability=a,
        logic_paths=logic_paths
    )

load_dotenv()
# 環境変数 OPENAI_API_KEY を使う
llm = ChatOpenAI(model=os.getenv("OPENAI_MODEL"), temperature=0)
semantic_normalizer_lambda = RunnableLambda(normalize_features_with_semantic)
parser = JsonOutputParser()

prompt = ChatPromptTemplate.from_template("""
以下の「脅威記述文」から、CVSSスコアリングのための特徴項目を抽出してください。
抽出すべき構造はJSON形式で、以下のキーを含めてください：

attack_vector: ["network", "usb", "wireless", "local", "physical"]
device_type: 例: "手術ロボット", "PACS", "CTスキャナー"
attack_type: 攻撃種別（例: "ファームウェア改ざん", "DoS", "盗聴"）
requires_authentication: true または false
requires_user_interaction: true または false
asset_category: 医療機器・情報システムの分類
data_type: 脅威記述文で影響を受けるデータの種類。以下のカテゴリから該当するものを選択（複数可）:
  - "personal_medical": 患者データ、患者個人情報、診療録、医療画像が影響を受ける場合
  - "diagnostic_imaging": DICOM画像、CT/MRI画像、X線画像が影響を受ける場合
  - "vital_biometric": 心電図、血圧、血糖値、体温、呼吸、脳波データが影響を受ける場合
  - "medication_protocol": 薬剤情報、投与量、治療計画、プロトコルが影響を受ける場合
  - "device_configuration": 機器設定、校正データ、メンテナンス記録が影響を受ける場合
  - "operational_admin": ユーザー権限、アクセスログ、監査証跡が影響を受ける場合
  - "public_research": 匿名化統計、研究データ、公開ガイドラインが影響を受ける場合
  ※必ず該当するものを選択してください。データ漏洩・改ざん・アクセスに関する記述がある場合は適切なカテゴリを選択。
impact_type: ["機密性重視", "完全性重視", "可用性重視", "複合"]

脅威記述文:
{threat_description}
出力フォーマット:
{format_instructions}
""")

# CVSSプロンプトを追加
cvss_prompt = ChatPromptTemplate.from_template("""
以下の「脅威記述文」と「抽出済み特徴」から、CVSSv3.1スコアリングのための追加情報を分析してください。
特に以下の観点で分析してください：

1. 攻撃の具体的な手法と必要なリソース
2. 攻撃による影響の範囲と深刻度
3. 医療機器の安全性・有効性への影響
4. 患者への直接的・間接的リスク

脅威記述文: {threat_description}
抽出済み特徴: {extracted_features}

分析結果をJSON形式で出力してください。
{format_instructions}
""")

# メインのチェーン
chain = (
    {"threat_description": RunnableLambda(lambda x: x), "format_instructions": RunnableLambda(lambda _: parser.get_format_instructions())}
    | prompt
    | llm
    | parser
    | semantic_normalizer_lambda
)

# CVSS計算を含む拡張チェーン
def calculate_cvss_with_ai(threat_description: str) -> dict:
    """脅威記述からCVSSスコアを計算"""
    # Step 1: 特徴抽出
    features = chain.invoke(threat_description)
    
    # Step 2: CVSSメトリクス決定
    cvss_metrics = determine_cvss_from_features(features, threat_description)
    
    # Step 3: CVSSスコア計算（共通モジュールを使用）
    calculator = CVSSCalculator()
    base_score = calculator.calculate_cvss_score(cvss_metrics)
    severity = calculator.get_severity_rating(base_score)
    
    # 結果をまとめる
    return {
        "threat_description": threat_description,
        "extracted_features": features,
        "cvss_metrics": {
            "attack_vector": cvss_metrics.attack_vector,
            "attack_complexity": cvss_metrics.attack_complexity,
            "privileges_required": cvss_metrics.privileges_required,
            "user_interaction": cvss_metrics.user_interaction,
            "scope": cvss_metrics.scope,
            "confidentiality_impact": cvss_metrics.confidentiality,
            "integrity_impact": cvss_metrics.integrity,
            "availability_impact": cvss_metrics.availability,
            "base_score": base_score,
            "severity": severity
        },
        "logic_tree_paths": cvss_metrics.logic_paths
    }

# CVSS計算付きバッチ処理関数
def process_threats_with_cvss(threat_descriptions: list) -> list:
    """脅威リストを処理してCVSSスコアを含む結果を返す"""
    results = []
    
    print("🧪 CVSS計算付きバッチ処理を開始します...\n")
    
    for threat in tqdm(threat_descriptions):
        try:
            result = calculate_cvss_with_ai(threat)
            results.append(result)
        except Exception as e:
            results.append({
                "threat_description": threat,
                "error": str(e)
            })
    
    return results

# テスト実行
if __name__ == "__main__":
    # テスト
    # 脅威文リスト（20件）
    threat_descriptions = [
    "攻撃者がUSBメモリを介して輸液ポンプにマルウェアを仕込み、不正操作を可能にした。",
    "外部ネットワークからAPIに未認証アクセスされ、患者データが漏洩した。",
    "手術ロボットのファームウェアを改ざんすることで、手術中の誤動作を引き起こした。",
    "攻撃者が院内Wi-Fiを介して心電図モニタに接続し、データを傍受した。",
    "医療情報システムに対するDDoS攻撃により、電子カルテへのアクセスが不能になった。",
    "攻撃者がパスワード総当たりでリモートアクセスを突破し、MRI画像を改ざんした。",
    "フィッシングメールを通じてオペレーターが悪意あるソフトウェアを起動してしまった。",
    "放射線治療装置における診断アルゴリズムが、AIの学習データ改ざんにより誤診を誘発。",
    "医療用データベースのSQLインジェクション脆弱性を突かれ、投薬記録が書き換えられた。",
    "Bluetooth経由でペースメーカーに接続され、電気信号パターンが改変された。",
    "攻撃者が内部ネットワークからHISにアクセスし、アクセスログを削除した。",
    "遠隔医療用端末にマルウェアを送り込み、医師の指示が偽装された。",
    "手術映像を録画しているカメラの設定が無線経由で変更され、記録が停止した。",
    "サプライチェーンを経由して脆弱なライブラリが混入し、改ざんが可能になった。",
    "攻撃者が診断装置のUSB診断ポートを通じてアクセスし、測定精度を下げる操作を行った。",
    "外部からCTスキャナーの診断設定を変更され、過剰な放射線照射が行われた。",
    "医療AIが敵対的学習により、特定条件下で誤った診断を返すようになっていた。",
    "医療機器のアップデートパッケージに不正な署名があり、バックドアがインストールされた。",
    "RFIDタグ付き患者情報が近距離無線で読み取られ、個人情報が漏洩した。",
    "IoMTデバイス群が同時に外部から制御され、意図しないタイミングで停止処理が実行された。"
    ]

    # CVSS計算を含む処理を実行
    cvss_results = process_threats_with_cvss(threat_descriptions)
    
    # 結果を保存
    with open("cvss_extraction_results.json", "w", encoding="utf-8") as f:
        json.dump(cvss_results, f, indent=2, ensure_ascii=False)
    
    print("\n✅ 完了しました。出力: cvss_extraction_results.json")
    
    # 統計情報を表示
    print("\n📊 CVSS統計:")
    severities = {}
    for result in cvss_results:
        if "cvss_metrics" in result:
            severity = result["cvss_metrics"]["severity"]
            severities[severity] = severities.get(severity, 0) + 1
    
    for severity, count in sorted(severities.items()):
        print(f"  {severity}: {count}件")