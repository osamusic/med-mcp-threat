from sentence_transformers import SentenceTransformer
import numpy as np
from typing import List, Dict, Any, Optional
import json
import os

class OptimizedSemanticNormalizer:
    """最適化されたSentenceTransformerベースのセマンティック正規化"""
    
    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        """
        初期化
        Args:
            model_name: 使用するSentenceTransformerモデル名
        """
        self.model = SentenceTransformer(model_name)
        self.embeddings_cache = {}
        self._initialize_optimized_embeddings()
    
    def _initialize_optimized_embeddings(self):
        """最適化された参照文とエンベディングを初期化"""
        
        # 医療特化語彙を大幅に拡充したデータタイプの参照文
        self.data_type_references = {
            "personal_medical": [
                "患者の個人医療情報や診療データ",
                "患者データベースの個人識別情報",
                "診療録、カルテ、医療記録",
                "患者の病歴や既往歴情報",
                "医療保険情報や患者登録データ",
                "個人の健康状態記録",
                "患者プロファイルと医療履歴",
                "個人医療データの機密情報"
            ],
            "diagnostic_imaging": [
                "CT、MRI、X線などの医療画像データ",
                "DICOM形式の診断画像ファイル",
                "放射線画像や超音波画像",
                "医療スキャン結果と画像診断",
                "レントゲン写真や断層撮影",
                "画像診断データとスキャン結果",
                "医療用撮影画像と診断映像",
                "CT画像データとMRI撮影結果"
            ],
            "vital_biometric": [
                "血圧、心拍数、体温などのバイタルサイン",
                "心電図波形や脳波データ",
                "血糖値測定結果と生体指標",
                "呼吸数や酸素飽和度の測定値",
                "生体認証データと生理学的指標",
                "リアルタイム生体監視データ",
                "血圧測定値と心拍変動データ",
                "バイタルサイン記録と生体情報"
            ],
            "medication_protocol": [
                "薬剤処方情報と投薬記録",
                "治療プロトコルと医療手順",
                "薬物投与量と処方箋データ",
                "治療計画と薬剤管理情報",
                "医薬品データベースと薬効情報",
                "処方箋記録と薬剤相互作用データ",
                "投薬スケジュールと治療ガイドライン",
                "薬剤情報システムと処方管理"
            ],
            "device_configuration": [
                "医療機器の設定パラメータ",
                "機器校正データと調整値",
                "装置設定ファイルと構成情報",
                "医療機器のファームウェア設定",
                "機器制御パラメータと動作設定",
                "装置キャリブレーションデータ",
                "機器設定ファイルと構成管理",
                "システム設定と機器調整情報"
            ],
            "operational_admin": [
                "ユーザーアクセス権限と認証情報",
                "システム操作ログと監査証跡",
                "管理者権限とアクセス制御データ",
                "ユーザー管理記録と認証履歴",
                "システム管理ログと操作追跡",
                "アクセス記録と権限管理情報",
                "管理運用データと監査ログ",
                "ユーザーアクセス記録と認証管理"
            ],
            "public_research": [
                "匿名化された研究統計データ",
                "公開医学研究のデータセット",
                "非識別化された分析結果",
                "研究目的の集計統計情報",
                "公開ガイドラインと標準データ",
                "学術研究用の匿名データ",
                "統計分析結果と研究報告",
                "公開医療統計と研究データ"
            ]
        }
        
        # 攻撃ベクトルの参照文（医療環境特化）
        self.attack_vector_references = {
            "network": [
                "インターネット経由のネットワーク攻撃",
                "外部ネットワークからの遠隔侵入",
                "ウェブベースの攻撃とAPI侵害",
                "オンライン経由の不正アクセス",
                "ネットワーク通信を利用した攻撃",
                "インターネット接続を悪用した侵入",
                "リモートネットワーク経由の攻撃"
            ],
            "usb": [
                "USBメモリを使用したマルウェア攻撃",
                "リムーバブルデバイス経由の感染",
                "USB診断ポートへの不正アクセス",
                "外部記憶媒体を利用した攻撃",
                "USBデバイスによるシステム侵害",
                "ポータブルメディア経由の脅威",
                "USB接続による物理的侵入"
            ],
            "wireless": [
                "Wi-Fi、Bluetooth経由の無線攻撃",
                "無線通信の傍受と中間者攻撃",
                "近距離無線による不正アクセス",
                "WiFi経由の無線ネットワーク侵害",
                "Bluetooth接続の悪用攻撃",
                "無線LAN経由の通信傍受",
                "ワイヤレス通信を標的とした攻撃"
            ],
            "local": [
                "ローカルシステムへの直接アクセス",
                "院内ネットワークからの内部攻撃",
                "隣接システム経由の侵入",
                "内部ネットワークでの横展開攻撃",
                "ローカルアクセス権限を悪用した攻撃",
                "内部システムからの不正操作",
                "院内LANを利用した攻撃"
            ],
            "physical": [
                "物理的機器への直接攻撃",
                "装置への物理的アクセスと破壊",
                "機器の物理的改ざんと盗難",
                "ハードウェアレベルの物理攻撃",
                "機器への直接的な物理操作",
                "装置の物理的破壊と妨害",
                "機器に対する物理的脅威"
            ]
        }
        
        # 影響タイプの参照文（医療リスク特化）
        self.impact_type_references = {
            "機密性重視": [
                "医療情報の漏洩と盗聴攻撃",
                "患者データの不正な閲覧",
                "機密医療情報への無許可アクセス",
                "医療記録の不正取得",
                "個人健康情報の盗取",
                "診療データの機密性侵害",
                "医療プライバシーの漏洩"
            ],
            "完全性重視": [
                "医療データの改ざんと不正変更",
                "診療記録の書き換え攻撃",
                "医療情報の完全性破壊",
                "治療データの偽装と改変",
                "医療記録の不正修正",
                "診断結果の改ざん攻撃",
                "医療データの整合性破壊"
            ],
            "可用性重視": [
                "医療システムの機能停止",
                "医療サービスの利用不能攻撃",
                "診療業務の中断と妨害",
                "医療機器の動作停止",
                "システムダウンによるサービス中断",
                "医療業務の可用性阻害",
                "診療システムの機能不全"
            ]
        }
        
        # エンベディングを事前計算
        self._precompute_embeddings()
    
    def _precompute_embeddings(self):
        """すべての参照文のエンベディングを事前計算"""
        
        # データタイプ
        for category, texts in self.data_type_references.items():
            embeddings = self.model.encode(texts)
            self.embeddings_cache[f"data_type_{category}"] = embeddings
        
        # 攻撃ベクトル
        for category, texts in self.attack_vector_references.items():
            embeddings = self.model.encode(texts)
            self.embeddings_cache[f"attack_vector_{category}"] = embeddings
        
        # 影響タイプ
        for category, texts in self.impact_type_references.items():
            embeddings = self.model.encode(texts)
            self.embeddings_cache[f"impact_type_{category}"] = embeddings
    
    def find_best_match(self, text: str, category_type: str, threshold: float = 0.55) -> Optional[str]:
        """
        テキストに最も近いカテゴリを見つける（最適化された閾値）
        
        Args:
            text: 分類したいテキスト
            category_type: "data_type", "attack_vector", "impact_type"のいずれか
            threshold: 類似度の閾値（最適化: 0.55）
        
        Returns:
            最も類似度の高いカテゴリ名、または閾値以下の場合None
        """
        if not text:
            return None
        
        # テキストのエンベディング
        text_embedding = self.model.encode([text])[0]
        
        # 各カテゴリとの類似度を計算
        best_score = -1
        best_category = None
        
        references = getattr(self, f"{category_type}_references", {})
        
        for category in references:
            cache_key = f"{category_type}_{category}"
            if cache_key in self.embeddings_cache:
                category_embeddings = self.embeddings_cache[cache_key]
                
                # コサイン類似度を計算
                similarities = np.dot(category_embeddings, text_embedding) / (
                    np.linalg.norm(category_embeddings, axis=1) * np.linalg.norm(text_embedding)
                )
                
                # 最大類似度
                max_similarity = np.max(similarities)
                
                if max_similarity > best_score and max_similarity >= threshold:
                    best_score = max_similarity
                    best_category = category
        
        return best_category
    
    def normalize_data_types(self, data_types: List[str]) -> List[str]:
        """データタイプのリストを正規化"""
        normalized = []
        
        for dt in data_types:
            # すでに正しいカテゴリの場合はそのまま使用
            if dt in self.data_type_references:
                normalized.append(dt)
            else:
                # セマンティック検索で最適なカテゴリを見つける
                best_match = self.find_best_match(dt, "data_type")
                if best_match:
                    normalized.append(best_match)
        
        return list(set(normalized))
    
    def normalize_attack_vector(self, attack_vector: str) -> str:
        """攻撃ベクトルを正規化"""
        if attack_vector in self.attack_vector_references:
            return attack_vector
        
        best_match = self.find_best_match(attack_vector, "attack_vector")
        return best_match if best_match else "local"  # デフォルト
    
    def normalize_impact_types(self, impact_types: List[str]) -> List[str]:
        """影響タイプのリストを正規化"""
        normalized = []
        
        for impact in impact_types:
            if impact in self.impact_type_references:
                normalized.append(impact)
            else:
                best_match = self.find_best_match(impact, "impact_type")
                if best_match:
                    normalized.append(best_match)
        
        return list(set(normalized))
    
    def extract_data_types_from_text(self, text: str, threshold: float = 0.7) -> List[str]:
        """
        テキストから関連するデータタイプを抽出（最適化された閾値）
        
        Args:
            text: 分析するテキスト
            threshold: 類似度の閾値（最適化: 0.7）
        
        Returns:
            抽出されたデータタイプのリスト
        """
        text_embedding = self.model.encode([text])[0]
        data_types = []
        
        for category, _ in self.data_type_references.items():
            cache_key = f"data_type_{category}"
            if cache_key in self.embeddings_cache:
                category_embeddings = self.embeddings_cache[cache_key]
                
                # コサイン類似度を計算
                similarities = np.dot(category_embeddings, text_embedding) / (
                    np.linalg.norm(category_embeddings, axis=1) * np.linalg.norm(text_embedding)
                )
                
                # 閾値を超える類似度があればカテゴリを追加
                if np.max(similarities) >= threshold:
                    data_types.append(category)
        
        return data_types