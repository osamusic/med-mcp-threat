"""
医療機器脅威生成システム - データ定義
Medical Device Threat Generator - Data Definitions

このファイルには以下のデータが含まれています:
- 医療機器タイプ
- 脅威テンプレート
- 対策データベース
- 資産分類
- データ分類
- 攻撃ベクトル定義
"""

# 医療機器タイプ
DEVICE_TYPES = [
    # 生命維持装置
    "人工呼吸器", "心臓ペースメーカー", "除細動器", "人工心肺装置", "ECMO装置",
    
    # 監視・測定機器
    "心電図モニター", "血圧計", "血糖値測定器", "パルスオキシメーター", "体温計",
    "中心静脈圧モニター", "脳圧モニター", "血液分析装置", "尿分析装置",
    
    # 画像診断装置
    "CTスキャナー", "MRI装置", "X線装置", "超音波装置", "内視鏡",
    "マンモグラフィ", "PET装置", "SPECT装置",
    
    # 治療機器
    "輸液ポンプ", "透析装置", "レーザー治療器", "電気メス", "麻酔器",
    "放射線治療装置", "リニアック", "ガンマナイフ", "高圧酸素治療装置",
    
    # 手術・処置機器
    "手術ロボット", "内視鏡手術装置", "電気メス", "麻酔器",
    "IVR装置", "カテーテル", "ステント",
    
    # 情報システム
    "電子カルテシステム", "PACS", "HIS", "薬剤管理システム", "検査情報システム",
    
    # 検査・分析機器
    "血液分析装置", "尿分析装置", "遠心分離機", "培養器", "顕微鏡",
    "聴力検査装置", "視力検査装置", "骨密度測定装置",
    
    # 専門機器
    "義肢制御装置", "歯科用X線", "口腔内カメラ",
    
    # AI/ML医療機器 ★新規追加
    "AI診断支援システム", "AI画像診断装置", "AI病理診断システム", 
    "AI創薬支援システム", "予測診断AIシステム", "手術支援AIロボット", 
    "AI投薬最適化システム",
    
    # IoMT・遠隔医療機器 ★新規追加
    "遠隔診療システム", "ウェアラブル心電計", "スマート血圧計",
    "遠隔モニタリングシステム", "在宅人工呼吸器", "IoMTセンサー",
    "テレヘルスプラットフォーム"
]

# 脅威テンプレート（カテゴリ別）
THREAT_TEMPLATES = {
    "ネットワーク": [
        "SQLインジェクション攻撃", "クロスサイトスクリプティング", "DoS攻撃",
        "中間者攻撃", "セッションハイジャック", "DNSスプーフィング",
        "ARPスプーフィング", "TCPハイジャック", "IPスプーフィング",
        "ポートスキャン", "脆弱性スキャン", "ネットワーク盗聴",
        "院内ネットワーク侵入", "HIS不正アクセス", "PACS改ざん",
        "電子カルテ漏洩", "DICOM通信盗聴", "HL7メッセージ改ざん"
    ],
    
    "物理": [
        "物理的破壊", "ハードウェア改ざん", "ファームウェア改ざん",
        "USBマルウェア", "外部記憶媒体感染", "コンソールアクセス",
        "ケーブル盗聴", "電磁波攻撃", "温度攻撃", "電源攻撃",
        "デバイス盗難", "保守ポート悪用", "診断ポート攻撃",
        "物理的不正アクセス", "環境センサー妨害"
    ],
    
    "無線": [
        "Wi-Fi攻撃", "Bluetooth攻撃", "NFC攻撃", "ZigBee攻撃",
        "RF妨害", "電波ジャミング", "無線通信盗聴", "リプレイ攻撃",
        "信号干渉", "周波数妨害", "患者モニタリング干渉",
        "医療テレメトリ攻撃", "無線LAN侵入"
    ],
    
    "ソフトウェア": [
        "バッファオーバーフロー", "ゼロデイ攻撃", "マルウェア感染",
        "ランサムウェア", "トロイの木馬", "ワーム感染",
        "ルートキット", "スパイウェア", "アドウェア",
        "デシリアライゼーション攻撃", "コード実行攻撃",
        "メモリ破損攻撃", "競合状態攻撃", "整数オーバーフロー"
    ],
    
    # AI/ML特有の脅威（新規追加）
    "AI/ML": [
        "データポイズニング", "モデル逆転攻撃", "敵対的サンプル攻撃",
        "モデル盗用", "説明可能性攻撃", "バックドア攻撃",
        "学習データ漏洩", "モデル推論攻撃", "フェデレーテッド学習攻撃",
        "AIバイアス悪用", "転移学習汚染", "ディープフェイク医療画像"
    ],
    
    # IoMT/遠隔医療特有の脅威（新規追加）
    "IoMT/遠隔医療": [
        "5Gネットワーク遅延攻撃", "エッジコンピューティング侵害", "在宅ネットワーク侵入",
        "遠隔診療なりすまし", "ウェアラブルデバイス改ざん", "クラウドAPI攻撃",
        "マルチテナント分離失敗", "遠隔操作権限奪取", "バイタルデータ改ざん",
        "遠隔手術妨害", "IoTボットネット感染", "プライバシー侵害攻撃"
    ],
    
    # サプライチェーン攻撃（新規追加）
    "サプライチェーン": [
        "偽造部品混入", "悪意のあるファームウェア", "サードパーティライブラリ汚染",
        "開発環境侵害", "配送過程での改ざん", "保守業者なりすまし",
        "アップデートサーバー侵害", "証明書偽造", "SBOM改ざん",
        "ODM/OEM侵害", "チップレベルバックドア", "製造工程汚染"
    ]
}

# 対策データベース（カテゴリ別）
COUNTERMEASURES_DB = {
    "ネットワーク": [
        "ファイアウォールの設定", "侵入検知システム(IDS)", "VPN接続",
        "ネットワークセグメンテーション", "TLS/SSL暗号化", "多要素認証",
        "アクセス制御リスト", "Web Application Firewall", "DoS対策",
        "ネットワーク監視", "LDAP統合認証", "シングルサインオン(SSO)",
        "ロールベースアクセス制御(RBAC)", "ネットワーク暗号化"
    ],
    
    "物理": [
        "物理的アクセス制御", "セキュアブート", "ハードウェアセキュリティモジュール",
        "改ざん検知", "環境監視", "電磁シールド", "セキュリティケージ",
        "バイオメトリクス認証", "監視カメラ", "警備システム", "物理セキュリティ監査",
        "ハードウェア暗号化", "TPM(Trusted Platform Module)"
    ],
    
    "無線": [
        "暗号化プロトコル強化", "周波数ホッピング", "信号強度監視",
        "認証機能強化", "通信範囲制限", "干渉検知", "スペクトラム管理",
        "デジタル署名", "無線侵入検知", "RF遮蔽", "無線認証統合",
        "証明書ベース認証"
    ],
    
    "ソフトウェア": [
        "セキュアコーディング", "入力値検証", "メモリ保護",
        "コード署名", "パッチ管理", "脆弱性スキャン", "ランタイム保護",
        "アプリケーション分離", "サンドボックス", "動的解析", "OSハードニング",
        "最小権限の原則", "セキュリティ設定管理"
    ],
    
    "システム運用": [
        "監査ログ記録", "ログ集中管理", "セキュリティ情報・イベント管理(SIEM)",
        "データ暗号化", "データベース暗号化", "ファイルシステム暗号化",
        "キー管理システム", "バックアップ暗号化", "権限管理システム",
        "セキュリティポリシー管理", "定期セキュリティ監査", "アクセスレビュー"
    ],
    
    "認証・認可": [
        "Active Directory統合", "LDAP認証", "多要素認証(MFA)", 
        "シングルサインオン(SSO)", "ロールベースアクセス制御(RBAC)",
        "属性ベースアクセス制御(ABAC)", "特権アクセス管理(PAM)",
        "認証統合基盤", "ID管理システム", "セッション管理"
    ],
    
    "データ保護": [
        "データ暗号化", "データベース暗号化", "ファイル暗号化",
        "通信暗号化", "データ匿名化", "データマスキング",
        "データ損失防止(DLP)", "データバックアップ", "データ完全性検証",
        "データ保持ポリシー"
    ],
    
    "AI/ML": [
        "モデル検証・テスト", "学習データ品質管理", "差分プライバシー",
        "敵対的学習", "モデルの説明可能性", "バイアス検出・軽減", 
        "データプロベナンス管理", "フェデレーテッドラーニング", 
        "AI倫理ガイドライン遵守", "継続的モニタリング"
    ],
    
    "IoMT/遠隔医療": [
        "エンドツーエンド暗号化", "デバイス認証", "セキュアプロビジョニング",
        "リアルタイム異常検知", "ネットワーク分離", "5Gセキュリティ",
        "患者プライバシー保護", "遠隔アクセス制御", "緊急時フェイルセーフ",
        "テレヘルス規制遵守"
    ],
    
    "サプライチェーン": [
        "ベンダーセキュリティ評価", "ソフトウェア部品表(SBOM)", 
        "セキュア開発ライフサイクル", "第三者セキュリティ監査",
        "コンポーネント脆弱性管理", "サプライヤーリスク評価",
        "ハードウェア認証", "配送時セキュリティ", "インシデント対応計画",
        "継続的セキュリティ監視"
    ]
}

# 資産分類定義（安全性・有効性観点を含む）
ASSET_CLASSIFICATION = {
    # 生命維持・緊急対応資産 (最高価値)
    "life_critical": {
        "devices": [
            "人工呼吸器", "心臓ペースメーカー", "除細動器", "人工心肺装置", 
            "ECMO装置", "透析装置", "麻酔器", "高圧酸素治療装置"
        ],
        "asset_value": "critical",
        "availability_priority": "highest",  # 生命維持最優先
        "integrity_priority": "high",  # 動作精度重要
        "safety_class": "Class III (生命脅威)",
        "safety_criticality": "life_threatening"
    },
    
    # 安全機能・アラーム資産 (最高価値) ★新規追加
    "safety_function": {
        "devices": [
            "安全システム", "アラーム機能", "緊急停止", "フェイルセーフ",
            "インターロック", "安全監視", "警告システム"
        ],
        "asset_value": "critical",
        "integrity_priority": "highest",  # 安全機能の正確性
        "availability_priority": "highest",  # 安全機能の継続性
        "safety_class": "Safety Function",
        "safety_criticality": "safety_critical",
        "efficacy_critical": True
    },
    
    # 治療効果・投薬精度資産 (最高価値) ★新規追加
    "therapeutic_efficacy": {
        "devices": [
            "放射線治療装置", "リニアック", "ガンマナイフ", "レーザー治療器",
            "薬剤投与システム", "化学療法装置", "免疫療法システム"
        ],
        "asset_value": "critical",
        "integrity_priority": "highest",  # 治療精度最重要
        "availability_priority": "high",  # 治療継続性
        "confidentiality_priority": "high",  # 治療情報保護
        "safety_class": "Class III (治療クリティカル)",
        "safety_criticality": "therapeutic_critical",
        "efficacy_critical": True
    },
    
    # 薬剤・投薬システム資産 (高価値) ★新規追加
    "medication_systems": {
        "devices": [
            "薬剤管理システム", "自動調剤システム", "PCAポンプ", "薬剤投与ポンプ",
            "化学療法調製システム", "麻薬管理システム"
        ],
        "asset_value": "high",
        "integrity_priority": "highest",  # 薬剤安全性
        "confidentiality_priority": "high",  # 処方情報保護
        "availability_priority": "high",  # 継続投薬
        "safety_class": "Class II-III (薬剤クリティカル)",
        "safety_criticality": "medication_critical",
        "efficacy_critical": True
    },
    
    # 情報システム資産 (高価値)
    "information_systems": {
        "devices": [
            "電子カルテシステム", "PACS", "HIS", "検査情報システム",
            "薬剤情報システム", "医事システム", "予約システム"
        ],
        "asset_value": "high",
        "confidentiality_priority": "highest",  # 患者情報保護
        "integrity_priority": "high",  # データ正確性
        "safety_class": "Information System",
        "safety_criticality": "information_critical"
    },
    
    # 手術・治療資産 (高価値)
    "surgical_treatment": {
        "devices": [
            "手術ロボット", "内視鏡手術装置", "電気メス", "IVR装置",
            "カテーテル", "ステント", "インプラント"
        ],
        "asset_value": "high",
        "integrity_priority": "highest",  # 手術精度
        "availability_priority": "high",  # 手術継続性
        "safety_class": "Class III (手術クリティカル)",
        "safety_criticality": "surgical_critical",
        "efficacy_critical": True
    },
    
    # 診断・画像資産 (高価値)
    "diagnostic_imaging": {
        "devices": [
            "CTスキャナー", "MRI装置", "X線装置", "超音波装置", 
            "内視鏡", "マンモグラフィ", "PET装置", "SPECT装置"
        ],
        "asset_value": "high",
        "confidentiality_priority": "high",  # 画像プライバシー
        "integrity_priority": "high",  # 診断精度
        "safety_class": "Class II (診断クリティカル)",
        "safety_criticality": "diagnostic_critical",
        "efficacy_critical": True
    },
    
    # 生体監視・測定資産 (中〜高価値)
    "monitoring_measurement": {
        "devices": [
            "心電図モニター", "血糖値測定器", "血圧計", "体温計",
            "パルスオキシメーター", "血液分析装置", "尿分析装置",
            "中心静脈圧モニター", "脳圧モニター"
        ],
        "asset_value": "medium-high",
        "integrity_priority": "high",  # 測定精度重要
        "availability_priority": "high",  # 連続監視重要
        "safety_class": "Class I-II",
        "safety_criticality": "monitoring_critical",
        "efficacy_critical": True  # 治療判断に直結
    },
    
    # 補助・周辺資産 (中価値)
    "auxiliary_peripheral": {
        "devices": [
            "遠心分離機", "培養器", "顕微鏡", "聴力検査装置",
            "視力検査装置", "骨密度測定装置"
        ],
        "asset_value": "medium"
    },
    
    # 特殊・研究資産 (中価値)
    "specialized_research": {
        "devices": [
            "義肢制御装置", "歯科用X線", "口腔内カメラ"
        ],
        "asset_value": "medium"
    },
    
    # AI/ML診断・治療資産 (最高価値) ★新規追加
    "ai_ml_medical": {
        "devices": [
            "AI診断支援システム", "AI画像診断装置", "AI病理診断システム", 
            "AI創薬支援システム", "予測診断AIシステム", "手術支援AIロボット", 
            "AI投薬最適化システム"
        ],
        "asset_value": "critical",
        "integrity_priority": "highest",  # AI判断の正確性
        "confidentiality_priority": "high",  # 学習データ・モデル保護
        "availability_priority": "high",  # リアルタイム推論要求
        "safety_class": "AI Medical Device",
        "safety_criticality": "ai_decision_critical",
        "efficacy_critical": True,
        "transparency_required": True  # 説明可能性要求
    },
    
    # 遠隔医療・IoMT資産 (高価値) ★新規追加
    "telemedicine_iomt": {
        "devices": [
            "遠隔診療システム", "ウェアラブル心電計", "スマート血圧計",
            "遠隔モニタリングシステム", "在宅人工呼吸器", "IoMTセンサー",
            "テレヘルスプラットフォーム"
        ],
        "asset_value": "high",
        "availability_priority": "highest",  # 緊急時リアルタイム性
        "confidentiality_priority": "highest",  # 遠隔患者プライバシー
        "integrity_priority": "high",  # 遠隔診断精度
        "safety_class": "IoMT Device",
        "safety_criticality": "telemedicine_critical",
        "efficacy_critical": True,
        "real_time_critical": True
    }
}

# データ分類定義（安全性・有効性観点を含む）
DATA_CLASSIFICATION = {
    # 安全性・リスク管理データ (最高重要)
    "safety_risk_data": {
        "types": ["安全機能設定", "アラーム閾値", "緊急停止設定", "フェイルセーフパラメータ", 
                 "リスク分析データ", "ハザード情報", "安全限界値", "インターロック設定"],
        "integrity": "highest",  # 安全機能の正確性
        "availability": "highest",  # 安全機能の可用性
        "confidentiality": "high",
        "regulatory": "薬機法, ISO 14971, IEC 62304",
        "safety_critical": True
    },
    
    # 治療効果・投薬データ (最高重要)
    "therapeutic_efficacy_data": {
        "types": ["治療計画", "放射線量", "薬剤投与量", "治療プロトコル", "投薬スケジュール",
                 "化学療法レジメン", "手術計画", "治療効果測定", "副作用データ"],
        "integrity": "highest",  # 治療精度
        "confidentiality": "high",
        "availability": "high",
        "regulatory": "薬機法, 医師法, GCP",
        "efficacy_critical": True
    },
    
    # 診断精度・検査データ (高重要)
    "diagnostic_accuracy_data": {
        "types": ["診断アルゴリズム", "画像解析パラメータ", "検査基準値", "診断閾値",
                 "校正データ", "精度管理データ", "測定不確かさ", "品質管理データ"],
        "integrity": "highest",  # 診断精度
        "confidentiality": "high",
        "availability": "high",
        "regulatory": "薬機法, 臨床検査技師法",
        "efficacy_critical": True
    },
    
    # AI/MLモデル・学習データ (最高重要) ★新規追加
    "ai_ml_model_data": {
        "types": ["機械学習モデル", "学習データセット", "推論パラメータ", "AIアルゴリズム", 
                 "特徴量", "モデル重み", "ハイパーパラメータ", "トレーニングログ", "バイアス検出データ"],
        "confidentiality": "highest",  # モデル・データの知的財産保護
        "integrity": "highest",  # AI判断の正確性
        "availability": "high",  # リアルタイム推論要求
        "regulatory": "薬機法, AI倫理ガイドライン, ISO/IEC 23053, FDA AI/ML guidance",
        "safety_critical": True,
        "efficacy_critical": True,
        "explainability_required": True  # 医療AI説明責任
    },
    
    # 遠隔医療・IoMT通信データ (最高重要) ★新規追加
    "telemedicine_iomt_data": {
        "types": ["遠隔診療データ", "IoMTセンサーデータ", "リアルタイム生体情報", "通信ログ",
                 "遠隔モニタリングデータ", "ウェアラブルデータ", "在宅医療データ", "テレヘルスセッション"],
        "confidentiality": "highest",  # 患者プライバシー保護
        "integrity": "high",  # 遠隔診断精度
        "availability": "highest",  # 緊急時リアルタイム性
        "regulatory": "医療法, 遠隔診療ガイドライン, 個人情報保護法, 総務省IoMTガイドライン",
        "safety_critical": True,
        "real_time_critical": True  # 遠隔緊急対応
    },
    
    # 患者個人識別情報 (最高機密)
    "patient_pii": {
        "types": ["患者ID", "氏名", "住所", "連絡先", "保険情報"],
        "confidentiality": "highest",
        "regulatory": "個人情報保護法, 医療法"
    },
    
    # 診断・治療データ (高機密)
    "medical_records": {
        "types": ["診断結果", "検査データ", "画像データ", "処方情報", "手術記録"],
        "confidentiality": "high",
        "integrity": "highest",  # 誤診防止
        "regulatory": "医師法, 薬機法"
    },
    
    # バイタルサイン・生体データ (高機密)
    "vital_biometric": {
        "types": ["心電図", "血圧", "血糖値", "体温", "呼吸", "脳波"],
        "confidentiality": "high",
        "integrity": "high",
        "availability": "high"  # リアルタイム性重要
    },
    
    # 薬剤・治療プロトコル (高機密)
    "medication_protocol": {
        "types": ["薬剤情報", "投与量", "治療計画", "プロトコル"],
        "integrity": "highest",  # 生命に直結
        "confidentiality": "high"
    },
    
    # 機器設定・校正データ (中機密)
    "device_configuration": {
        "types": ["機器設定", "校正データ", "メンテナンス記録"],
        "integrity": "high",  # 機器精度
        "availability": "high"
    },
    
    # 運用・管理データ (中機密)
    "operational_admin": {
        "types": ["ユーザー権限", "アクセスログ", "監査証跡"],
        "integrity": "high",
        "confidentiality": "medium"
    },
    
    # 公開・研究データ (低機密)
    "public_research": {
        "types": ["匿名化統計", "研究データ", "公開ガイドライン"],
        "confidentiality": "low",
        "integrity": "medium"
    }
}

# CVSS関連定義
ATTACK_VECTORS = {
    "Network": "N", "Adjacent Network": "A", "Local": "L", "Physical": "P"
}

ATTACK_COMPLEXITY = {"Low": "L", "High": "H"}
PRIVILEGES_REQUIRED = {"None": "N", "Low": "L", "High": "H"}
USER_INTERACTION = {"None": "N", "Required": "R"}
SCOPE = {"Unchanged": "U", "Changed": "C"}
IMPACT_LEVELS = {"None": "N", "Low": "L", "High": "H"}

# 深刻度レーティング
SEVERITY_RATINGS = {
    "0.0": "None",
    "0.1-3.9": "Low", 
    "4.0-6.9": "Medium",
    "7.0-8.9": "High",
    "9.0-10.0": "Critical"
}

# CVSS決定ロジック用攻撃パターン定義
CVSS_ATTACK_PATTERNS = {
    # 攻撃ベクトル決定用パターン
    "usb_attacks": ["USBマルウェア", "USBメモリ", "リムーバブル", "外部記憶", "メモリスティック", "外部記憶媒体感染"],
    "wireless_attacks": ["Wi-Fi", "Bluetooth", "NFC", "無線", "ZigBee", "RF妨害", "ジャミング", "リプレイ", "テレメトリ", "無線LAN"],
    "hospital_network_attacks": ["院内ネットワーク", "HIS", "電子カルテ", "PACS", "HL7", "DICOM"],
    
    # 攻撃複雑度決定用パターン
    "high_complexity_attacks": [
        "バッファオーバーフロー", "競合状態攻撃", "サイドチャネル攻撃",
        "デシリアライゼーション攻撃", "型混乱攻撃", "ファームウェア改ざん",
        "電磁波干渉", "温度攻撃", "電源攻撃", "AIの学習データ改ざん",
        "敵対的学習","モデル逆転", "敵対的サンプル", "フェデレーテッド学習", "バックドア攻撃"
    ],
    "high_complexity_devices": [
        "手術ロボット", "ECMO", "リニアック", "ガンマナイフ", "人工心肺装置",
        "透析装置", "人工呼吸器", "除細動器", "放射線治療"
    ],
    
    # 必要権限決定用パターン
    "no_privileges_attacks": [
        "DoS攻撃", "盗聴", "ジャミング", "中間者攻撃", "DNSポイズニング",
        "パスワード攻撃", "物理的破壊", "盗難", "総当たり"
    ],
    "high_privileges_attacks": [
        "ファームウェア改ざん", "権限昇格", "システム設定変更",
        "ソフトウェア供給チェーン攻撃", "悪意のあるアップデート",
        "供給チェーン", "アクセスログ削除","証明書偽造", "SBOM改ざん", "悪意のあるファームウェア"
    ],
    
    # ユーザー操作決定用パターン
    "user_interaction_attacks": [
        "クロスサイトスクリプティング", "フィッシング", "ソーシャルエンジニアリング",
        "悪意のあるアップデート", "USBマルウェア", "ランサムウェア",
        "悪意あるソフトウェアを起動"
    ],
    "no_ui_attacks": [
        "DoS", "盗聴", "バッファオーバーフロー", "SQLインジェクション",
        "自動的に", "外部から","遠隔診療なりすまし", "ウェアラブル", "クラウドAPI攻撃"
    ],
    
    # スコープ決定用パターン
    "scope_change_attacks": [
        "ランサムウェア", "ワーム", "横展開", "供給チェーン攻撃",
        "権限昇格", "ドメイン侵害", "他のシステム","モデル盗用", "転移学習", "マルチテナント分離失敗"
    ],
    "networked_critical_devices": [
        "電子カルテ", "HIS", "PACS", "手術ロボット", "人工心肺装置",
        "薬剤管理システム", "中央監視システム"
    ],
    
    # CIA影響度決定用パターン
    "confidentiality_attacks": ["盗聴", "DICOM通信盗聴", "患者データ漏洩","AIモデル盗用", "バイタルデータ漏洩", "診断データ漏洩", "AIデータ漏洩"],
    "integrity_attacks": ["改ざん", "SQLインジェクション", "PACS改ざん","AI判断改ざん", "バイタルデータ改ざん", "診断データ改ざん", "AI推論改ざん"],
    "availability_attacks": ["DoS", "ジャミング", "RF干渉", "電磁波干渉","遠隔手術妨害", "エッジコンピューティング侵害", "在宅ネットワーク遅延", "AI推論停止"],
    "destructive_attacks": ["物理破壊", "温度攻撃", "電源攻撃"],
    "complex_attacks": ["ランサムウェア", "供給チェーン", "ファームウェア改ざん"],
    
    # 生命維持・緊急対応機器キーワード
    "life_critical_keywords": ["人工呼吸器", "ペースメーカー", "除細動器", "ECMO", "透析"],
    "diagnostic_keywords": ["CT", "MRI", "X線", "超音波", "内視鏡","AI診断支援システム", "AI画像診断装置", "AI病理診断システム", "遠隔診療システム", "IoMTセンサー"],
    "info_system_keywords": ["電子カルテ", "PACS", "HIS","テレヘルスプラットフォーム", "IoMTセンサー"]
}