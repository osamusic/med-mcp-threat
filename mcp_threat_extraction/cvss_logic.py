#!/usr/bin/env python3
"""
医療機器CVSS計算共通ロジックモジュール
threat_generator.pyとthreat_extraction.pyで共有される機能
"""

from typing import Dict, List, Tuple
from dataclasses import dataclass


@dataclass
class CVSSMetrics:
    """CVSSv3.1メトリクス"""
    attack_vector: str
    attack_complexity: str
    privileges_required: str
    user_interaction: str
    scope: str
    confidentiality: str
    integrity: str
    availability: str
    base_score: float = 0.0
    severity: str = "None"
    logic_paths: dict = None  # ロジックツリーの選択パスを記録
    
    def __post_init__(self):
        if self.logic_paths is None:
            self.logic_paths = {}

class CVSSCalculator:
    """CVSS計算クラス"""
       
    def calculate_cvss_score(self, metrics: CVSSMetrics) -> float:
        """CVSSv3.1ベーススコアを計算"""
        # Impact Sub Score
        iss_base = 1 - ((1 - self._get_impact_value(metrics.confidentiality)) * 
                       (1 - self._get_impact_value(metrics.integrity)) * 
                       (1 - self._get_impact_value(metrics.availability)))
        
        if metrics.scope == "U":
            impact = 6.42 * iss_base
        else:
            impact = 7.52 * (iss_base - 0.029) - 3.25 * ((iss_base - 0.02) ** 15)
        
        # Exploitability Sub Score
        exploitability = (8.22 * self._get_av_value(metrics.attack_vector) * 
                         self._get_ac_value(metrics.attack_complexity) * 
                         self._get_pr_value(metrics.privileges_required, metrics.scope) * 
                         self._get_ui_value(metrics.user_interaction))
        
        if impact <= 0:
            return 0.0
        
        if metrics.scope == "U":
            base_score = min(impact + exploitability, 10.0)
        else:
            base_score = min(1.08 * (impact + exploitability), 10.0)
        
        return round(base_score, 1)
    
    def _get_impact_value(self, impact: str) -> float:
        values = {"N": 0.0, "L": 0.22, "H": 0.56}
        return values[impact]
    
    def _get_av_value(self, av: str) -> float:
        values = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
        return values[av]
    
    def _get_ac_value(self, ac: str) -> float:
        values = {"L": 0.77, "H": 0.44}
        return values[ac]
    
    def _get_pr_value(self, pr: str, scope: str) -> float:
        if scope == "U":
            values = {"N": 0.85, "L": 0.62, "H": 0.27}
        else:
            values = {"N": 0.85, "L": 0.68, "H": 0.50}
        return values[pr]
    
    def _get_ui_value(self, ui: str) -> float:
        values = {"N": 0.85, "R": 0.62}
        return values[ui]
    
    def get_severity_rating(self, score: float) -> str:
        """CVSSスコアから深刻度を判定"""
        if score == 0.0:
            return "None"
        elif score <= 3.9:
            return "Low"
        elif score <= 6.9:
            return "Medium"
        elif score <= 8.9:
            return "High"
        else:
            return "Critical"

class CVSSLogicEngine:
    """CVSS決定ロジックエンジン"""
    
    def __init__(self, asset_classification, data_classification, attack_patterns):
        self.asset_classification = asset_classification
        self.data_classification = data_classification
        self.attack_patterns = attack_patterns
    
    def determine_attack_vector_with_path(self, threat_category: str, threat_name: str, device_type: str = "", 
                                        context: str = "generator") -> Tuple[str, dict]:
        """攻撃ベクトルを決定し、ロジックパスを記録"""
        path = {
            "decision_tree": "攻撃ベクトル決定フロー（医療機器版）",
            "checks": [],
            "reasoning": ""
        }
        
        # USBやリムーバブルメディア攻撃（院内での広範囲使用を考慮）
        for attack in self.attack_patterns["usb_attacks"]:
            if attack in threat_name:
                path["checks"].append(f"USB攻撃パターン検出: '{attack}' → YES")
                # 院内USBメモリの使用パターンを考慮
                if "保守" in threat_name or "メンテナンス" in threat_name or "技術者" in threat_name:
                    path["checks"].append("保守/メンテナンス/技術者 → Physical")
                    path["reasoning"] = "保守時の物理アクセスとして評価（医療機器の保守業務特性を考慮）"
                    path["result"] = "AV:P (Physical)"
                    return "P", path
                elif "外部" in threat_name or "業者" in threat_name:
                    path["checks"].append("外部業者アクセス → Physical")
                    path["reasoning"] = "外部業者による物理アクセスとして評価"
                    path["result"] = "AV:P (Physical)"
                    return "P", path
                else:
                    path["checks"].append("院内スタッフの日常使用 → Adjacent")
                    path["reasoning"] = "院内でのUSBメモリ共有慣行を考慮した隣接ネットワーク評価"
                    path["result"] = "AV:A (Adjacent - 院内USBネットワーク)"
                    return "A", path
        
        # 無線インターフェース攻撃
        if any(w in threat_name for w in self.attack_patterns["wireless_attacks"]):
            path["checks"].append("無線インターフェース (Wi-Fi/Bluetooth/NFC) → YES")
            path["reasoning"] = "無線通信による隣接ネットワーク攻撃"
            path["result"] = "AV:A (Adjacent Network)"
            return "A", path
        
        # 院内ネットワーク経由の攻撃
        for attack in self.attack_patterns["hospital_network_attacks"]:
            if attack in threat_name:
                path["checks"].append(f"院内ネットワーク攻撃: '{attack}' → YES")
                path["reasoning"] = "病院内ネットワークセグメント内での攻撃として評価"
                path["result"] = "AV:A (Adjacent Network)"
                return "A", path
        
        # ネットワーク攻撃の判定（カテゴリベース）
        if threat_category == "ネットワーク" or any(n in threat_name for n in ["ネットワーク", "API", "リモート", "外部"]):
            path["checks"].append("ネットワーク攻撃 → YES")
            # 院内ネットワーク/HIS/PACS/DICOM
            if any(h in threat_name for h in ["院内", "HIS", "PACS", "DICOM"]):
                path["checks"].append("院内ネットワーク/HIS/PACS/DICOM → YES")
                path["reasoning"] = "院内ネットワーク内での攻撃"
                path["result"] = "AV:A (Adjacent)"
                return "A", path
            else:
                path["checks"].append("院内ネットワーク/HIS/PACS/DICOM → NO")
                if "リモート" in threat_name or "インターネット" in threat_name:
                    path["checks"].append("リモート/インターネット攻撃 → Network")
                    path["reasoning"] = "インターネット経由のリモート攻撃"
                    path["result"] = "AV:N (Network)"
                    return "N", path
                elif "SQL" in threat_name or "Web" in threat_name:
                    path["checks"].append("SQL/Web攻撃 → Network")
                    path["reasoning"] = "Webアプリケーション経由の攻撃"
                    path["result"] = "AV:N (Network)"
                    return "N", path
                else:
                    path["reasoning"] = "ネットワーク攻撃として評価"
                    path["result"] = "AV:N (Network)"
                    return "N", path
        
        # 物理攻撃
        if threat_category == "物理" or "物理" in threat_name:
            path["checks"].append("物理攻撃 → YES")
            # 直接的な物理アクセスか、ローカルアクセスかを判定
            if any(direct in threat_name for direct in ["破壊", "盗難", "改ざん", "直接"]):
                path["checks"].append("直接物理攻撃 → Physical")
                path["reasoning"] = "機器への直接的な物理アクセスが必要な攻撃"
                path["result"] = "AV:P (Physical)"
                return "P", path
            else:
                path["checks"].append("ローカル物理攻撃 → Local")
                path["reasoning"] = "ローカルシステムレベルでの物理的操作"
                path["result"] = "AV:L (Local)"
                return "L", path
        
        # 無線カテゴリ
        if threat_category == "無線":
            path["checks"].append("無線攻撃 → Adjacent")
            path["reasoning"] = "無線通信による隣接ネットワーク攻撃"
            path["result"] = "AV:A (Adjacent)"
            return "A", path
        
        # デフォルト（ソフトウェアやその他）
        if threat_category == "ソフトウェア":
            # ソフトウェア攻撃の具体的な種類で判定
            if any(remote in threat_name for remote in ["API", "Web", "外部", "インターネット"]):
                path["checks"].append("リモートソフトウェア攻撃 → Network")
                path["reasoning"] = "ネットワーク経由のソフトウェア攻撃"
                path["result"] = "AV:N (Network)"
                return "N", path
            elif any(adjacent in threat_name for adjacent in ["院内", "LAN", "内部ネットワーク"]):
                path["checks"].append("院内ソフトウェア攻撃 → Adjacent")
                path["reasoning"] = "院内ネットワーク経由のソフトウェア攻撃"
                path["result"] = "AV:A (Adjacent)"
                return "A", path
            else:
                path["checks"].append("ローカルソフトウェア攻撃 → Local")
                path["reasoning"] = "ローカルシステムでのソフトウェア攻撃"
                path["result"] = "AV:L (Local)"
                return "L", path
        else:
            path["checks"].append("その他（デフォルト）")
            path["reasoning"] = "デフォルトローカル攻撃として評価"
            path["result"] = "AV:L (Local)"
            return "L", path
    
    def determine_attack_complexity_with_path(self, threat_name: str, device_type: str) -> Tuple[str, dict]:
        """攻撃複雑度を決定し、ロジックパスを記録"""
        path = {
            "decision_tree": "攻撃複雑度決定フロー（医療機器版）",
            "checks": [],
            "reasoning": ""
        }
        
        # 高複雑度の攻撃
        for attack in self.attack_patterns["high_complexity_attacks"]:
            if attack in threat_name:
                path["checks"].append(f"高複雑度攻撃検出: '{attack}' → High")
                path["reasoning"] = f"{attack}は高度な技術知識と専門ツールが必要な攻撃"
                path["result"] = "AC:H (High)"
                return "H", path
        
        # 医療機器固有の複雑度判定
        for device in self.attack_patterns["high_complexity_devices"]:
            if device in device_type:
                # 攻撃の種類と機器の複雑度を組み合わせて判定
                if any(complex_attack in threat_name for complex_attack in [
                    "ファームウェア", "制御システム", "アルゴリズム", "プロトコル", "暗号化"
                ]):
                    path["checks"].append(f"高複雑度医療機器 + 高度攻撃: '{device}' → High")
                    path["reasoning"] = f"{device}への高度な攻撃手法は高い技術的複雑度を要求"
                    path["result"] = "AC:H (High)"
                    return "H", path
                elif any(simple_attack in threat_name for simple_attack in [
                    "DoS", "盗聴", "パスワード", "設定変更", "アクセス"
                ]):
                    path["checks"].append(f"高複雑度医療機器 + 単純攻撃: '{device}' → Low")
                    path["reasoning"] = f"{device}でも単純な攻撃手法は比較的実行しやすい"
                    path["result"] = "AC:L (Low)"
                    return "L", path
                else:
                    path["checks"].append(f"高複雑度医療機器: '{device}' → High (デフォルト)")
                    path["reasoning"] = f"{device}は複雑な制御システムを持つため攻撃も複雑化"
                    path["result"] = "AC:H (High)"
                    return "H", path
        
        # デフォルト判定（攻撃手法ベース）
        if any(simple in threat_name for simple in [
            "DoS", "盗聴", "パスワード", "設定", "アクセス", "USB", "無線"
        ]):
            path["checks"].append("単純攻撃手法 → Low")
            path["reasoning"] = "比較的実行しやすい攻撃手法"
            path["result"] = "AC:L (Low)"
            return "L", path
        else:
            path["checks"].append("一般的攻撃（デフォルト高複雑度）")
            path["reasoning"] = "詳細不明な攻撃は安全側評価で高複雑度とする"
            path["result"] = "AC:H (High)"
            return "H", path
    
    def determine_privileges_required_with_path(self, threat_name: str, threat_category: str, 
                                              requires_auth: bool = None) -> Tuple[str, dict]:
        """必要権限を決定し、ロジックパスを記録"""
        path = {
            "decision_tree": "必要権限決定フロー（医療機器版）",
            "checks": [],
            "reasoning": ""
        }
        
        # 権限不要の攻撃
        for attack in self.attack_patterns["no_privileges_attacks"]:
            if attack in threat_name:
                path["checks"].append(f"権限不要攻撃: '{attack}' → None")
                path["reasoning"] = f"{attack}は事前の認証や権限取得が不要な攻撃"
                path["result"] = "PR:N (None)"
                return "N", path
        
        # 高権限必要な攻撃
        for attack in self.attack_patterns["high_privileges_attacks"]:
            if attack in threat_name:
                path["checks"].append(f"高権限必要攻撃: '{attack}' → High")
                path["reasoning"] = f"{attack}は管理者権限や特権アクセスが必要な攻撃"
                path["result"] = "PR:H (High)"
                return "H", path
        
        # 認証が必要な場合（threat_extraction用）
        if requires_auth is not None and requires_auth:
            path["checks"].append("認証が必要 → YES")
            # 攻撃の種類で必要権限を判定
            if any(admin in threat_name for admin in ["管理者", "システム", "設定変更", "権限昇格"]):
                path["checks"].append("高権限要求攻撃 → PR:H")
                path["result"] = "PR:H"
                return "H", path
            else:
                path["checks"].append("一般ユーザー権限 → PR:L")
                path["result"] = "PR:L"
                return "L", path
        
        # デフォルト判定（攻撃対象ベース）
        if any(system in threat_name for system in ["API", "Web", "インターフェース", "アプリケーション"]):
            path["checks"].append("アプリケーションレベル攻撃 → PR:L")
            path["reasoning"] = "アプリケーションレベルでの攻撃は一般ユーザー権限で実行可能"
            path["result"] = "PR:L"
            return "L", path
        else:
            path["checks"].append("一般的攻撃（デフォルト低権限）")
            path["reasoning"] = "医療機器の一般的な操作権限で実行可能な攻撃"
            path["result"] = "PR:L"
            return "L", path
    
    def determine_user_interaction_with_path(self, threat_name: str, 
                                           requires_ui: bool = None) -> Tuple[str, dict]:
        """ユーザー操作の必要性を決定し、ロジックパスを記録"""
        path = {
            "decision_tree": "ユーザー操作決定フロー（医療機器版）",
            "checks": [],
            "reasoning": ""
        }
        
        # ユーザー操作が必要な攻撃
        for attack in self.attack_patterns["user_interaction_attacks"]:
            if attack in threat_name:
                path["checks"].append(f"ユーザー操作必要攻撃: '{attack}' → Required")
                path["reasoning"] = f"{attack}は医療従事者による操作やクリックが必要な攻撃"
                path["result"] = "UI:R (Required)"
                return "R", path
        
        # 特徴データのrequires_user_interaction判定（threat_extraction用）
        if requires_ui is not None and requires_ui:
            path["checks"].append("requires_user_interaction: true")
            path["result"] = "UI:R"
            return "R", path
        
        # ユーザー操作不要攻撃
        for attack in self.attack_patterns["no_ui_attacks"]:
            if attack in threat_name:
                path["checks"].append(f"ユーザー操作不要攻撃: {attack} → YES")
                path["result"] = "UI:N"
                return "N", path
        
        # 医療機器特有のユーザー操作パターン
        if "診断" in threat_name or "検査" in threat_name or "設定" in threat_name:
            path["checks"].append("医療機器操作関連 → 操作が必要")
            path["reasoning"] = "医療従事者による機器操作や設定変更が攻撃の起点となる"
            path["result"] = "UI:R (Required)"
            return "R", path
        
        # デフォルト判定（攻撃性質ベース）
        if any(automated in threat_name for automated in ["自動", "システム", "プログラム", "スクリプト"]):
            path["checks"].append("自動化攻撃 → UI:N")
            path["reasoning"] = "自動化された攻撃はユーザー操作不要"
            path["result"] = "UI:N"
            return "N", path
        else:
            path["checks"].append("一般的攻撃（デフォルト不要）")
            path["reasoning"] = "医療機器攻撃の多くはユーザー操作不要で実行可能"
            path["result"] = "UI:N"
            return "N", path
    
    def determine_scope_with_path(self, threat_name: str, device_type: str) -> Tuple[str, dict]:
        """スコープを決定し、ロジックパスを記録"""
        path = {
            "decision_tree": "スコープ決定フロー（医療機器版）",
            "checks": [],
            "reasoning": ""
        }
        
        # スコープが変わる攻撃（他システムに影響）
        for attack in self.attack_patterns["scope_change_attacks"]:
            if attack in threat_name:
                path["checks"].append(f"スコープ変更攻撃: '{attack}' → Changed")
                path["reasoning"] = f"{attack}は初期侵入点から他のシステムや機器に影響を拡大する攻撃"
                path["result"] = "S:C (Changed)"
                return "C", path
        
        # 医療機器ネットワーク相互接続性の考慮
        for device in self.attack_patterns["networked_critical_devices"]:
            if device in device_type:
                # 攻撃の種類でスコープ影響を判定
                if any(spreading in threat_name for spreading in [
                    "ワーム", "ランサム", "横展開", "他システム", "ネットワーク全体"
                ]):
                    path["checks"].append(f"拡散型攻撃 + 重要機器: '{device}' → Changed")
                    path["reasoning"] = f"{device}への拡散型攻撃は他システムに影響を及ぼしやすい"
                    path["result"] = "S:C (Changed)"
                    return "C", path
                elif any(isolated in threat_name for isolated in [
                    "盗聴", "設定変更", "データ改ざん", "単体"
                ]):
                    path["checks"].append(f"単体攻撃 + 重要機器: '{device}' → Unchanged")
                    path["reasoning"] = f"{device}への単体攻撃は当該機器に限定"
                    path["result"] = "S:U (Unchanged)"
                    return "U", path
                else:
                    path["checks"].append(f"ネットワーク接続重要機器: '{device}' → Unchanged (デフォルト)")
                    path["reasoning"] = f"{device}への攻撃は当該機器に限定される（安全側評価）"
                    path["result"] = "S:U (Unchanged)"
                    return "U", path
        
        # デフォルト判定（攻撃の性質ベース）
        if any(spreading in threat_name for spreading in [
            "ネットワーク", "拡散", "伝播", "全体", "系全体"
        ]):
            path["checks"].append("ネットワーク拡散攻撃 → S:C")
            path["reasoning"] = "ネットワーク経由で拡散する攻撃はスコープ変更の可能性が高い"
            path["result"] = "S:C (Changed)"
            return "C", path
        else:
            path["checks"].append("一般的攻撃（デフォルト単体）")
            path["reasoning"] = "一般的な攻撃は単一機器に限定される（安全側評価）"
            path["result"] = "S:U (Unchanged)"
            return "U", path
    
    def determine_cia_impact_with_path(self, threat_name: str, device_type: str, 
                                     impact_types: List[str] = None, data_types: List[str] = None,
                                     attack_type: str = "") -> Tuple[str, str, str, dict]:
        """CIA影響度を決定し、ロジックパスを記録"""
        path = {
            "decision_tree": "CIA影響度決定フロー（医療機器版）",
            "checks": [],
            "reasoning": ""
        }
        
        if impact_types is None:
            impact_types = []
        if data_types is None:
            data_types = []
        
        # ベースとなる影響度を攻撃タイプから決定
        base_c, base_i, base_a, base_reasoning = self._get_base_impact_from_attack_with_path(threat_name, impact_types)
        path["checks"].extend(base_reasoning)
        
        # デバイスタイプから資産分類を特定
        asset_adjustment, asset_reasoning = self._get_asset_adjustment_with_path(device_type)
        path["checks"].extend(asset_reasoning)
        
        # 最終影響度を計算（資産調整のみ）
        final_c, c_reasoning = self._apply_asset_adjustment_only_with_path(base_c, asset_adjustment.get("confidentiality", 0), "機密性")
        final_i, i_reasoning = self._apply_asset_adjustment_only_with_path(base_i, asset_adjustment.get("integrity", 0), "完全性")
        final_a, a_reasoning = self._apply_asset_adjustment_only_with_path(base_a, asset_adjustment.get("availability", 0), "可用性")
        
        path["checks"].extend([c_reasoning, i_reasoning, a_reasoning])
        path["reasoning"] = "医療機器の資産分類を考慮してCIA影響度を決定"
        path["result"] = f"最終CIA: C:{final_c}, I:{final_i}, A:{final_a}"
        
        return final_c, final_i, final_a, path
    
    def _get_base_impact_from_attack_with_path(self, threat_name: str, impact_types: List[str] = None) -> Tuple[str, str, str, List[str]]:
        """攻撃タイプから基本影響度を決定し、推論過程を記録（各CIA属性を独立評価）"""
        if impact_types is None:
            impact_types = []
        reasoning = ["Step 1: 攻撃タイプ別基本影響度の決定（各CIA属性を独立評価）"]
        
        # 初期値を設定
        confidentiality = "L"
        integrity = "L" 
        availability = "L"
        
        # 機密性への影響を評価
        if "機密性重視" in impact_types:
            confidentiality = "H"
            reasoning.append("機密性重視攻撃フラグ → C:H")
        
        if any(conf in threat_name for conf in ["漏洩", "盗聴", "傍受", "搾取", "不正取得"]):
            confidentiality = "H"
            conf_keywords = [w for w in ["漏洩", "盗聴", "傍受", "搾取", "不正取得"] if w in threat_name]
            reasoning.append(f"機密性攻撃キーワード検出: {conf_keywords} → C:H")
        
        for attack in self.attack_patterns["confidentiality_attacks"]:
            if attack in threat_name:
                confidentiality = "H"
                reasoning.append(f"機密性攻撃パターン: '{attack}' → C:H")
                break
        
        # 完全性への影響を評価
        if "完全性重視" in impact_types:
            integrity = "H"
            reasoning.append("完全性重視攻撃フラグ → I:H")
        
        if any(integ in threat_name for integ in ["改ざん", "書き換え", "偽装", "変更", "操作"]):
            integrity = "H"
            integ_keywords = [w for w in ["改ざん", "書き換え", "偽装", "変更", "操作"] if w in threat_name]
            reasoning.append(f"完全性攻撃キーワード検出: {integ_keywords} → I:H")
        
        for attack in self.attack_patterns["integrity_attacks"]:
            if attack in threat_name:
                integrity = "H"
                reasoning.append(f"完全性攻撃パターン: '{attack}' → I:H")
                break
        
        # 可用性への影響を評価
        if "可用性重視" in impact_types:
            availability = "H"
            reasoning.append("可用性重視攻撃フラグ → A:H")
        
        if any(avail in threat_name for avail in ["停止", "不能", "DoS", "ジャミング", "妨害", "遮断"]):
            availability = "H"
            avail_keywords = [w for w in ["停止", "不能", "DoS", "ジャミング", "妨害", "遮断"] if w in threat_name]
            reasoning.append(f"可用性攻撃キーワード検出: {avail_keywords} → A:H")
        
        for attack in self.attack_patterns["availability_attacks"]:
            if attack in threat_name:
                availability = "H"
                reasoning.append(f"可用性攻撃パターン: '{attack}' → A:H")
                break
        
        # 破壊・物理攻撃の評価
        for attack in self.attack_patterns["destructive_attacks"]:
            if attack in threat_name:
                integrity = "H"
                availability = "H"
                reasoning.append(f"破壊・物理攻撃: '{attack}' → I:H, A:H")
                break
        
        # 複合影響攻撃の評価
        for attack in self.attack_patterns["complex_attacks"]:
            if attack in threat_name:
                if confidentiality == "L":
                    confidentiality = "L"  # 既に評価済みなら維持
                integrity = "H"
                availability = "H"
                reasoning.append(f"複合影響攻撃: '{attack}' → I:H, A:H")
                break
        
        # ネットワーク系攻撃の特別処理
        if any(network in threat_name for network in ["ネットワーク", "API", "Web", "リモート"]):
            if confidentiality == "L":
                confidentiality = "H"
                reasoning.append("ネットワーク系攻撃 → C:H（通常ネットワーク経由で情報取得可能）")
        
        
        reasoning.append(f"最終基本影響度: C:{confidentiality}, I:{integrity}, A:{availability}")
        return confidentiality, integrity, availability, reasoning
    
    def _get_asset_adjustment_with_path(self, device_type: str) -> Tuple[Dict[str, int], List[str]]:
        """デバイスタイプから資産調整値を取得し、推論過程を記録"""
        reasoning = ["Step 2: 医療機器資産分類による調整"]
        
        for asset_class, details in self.asset_classification.items():
            if any(device in device_type for device in details.get("devices", [])):
                adjustment = {"confidentiality": 0, "integrity": 0, "availability": 0}
                reasoning.append(f"資産分類: {asset_class} → '{device_type}'")
                
                # 優先度に基づく調整
                if details.get("confidentiality_priority") == "highest":
                    adjustment["confidentiality"] = 2
                    reasoning.append("→ 機密性: +2段階 (最高優先度)")
                elif details.get("confidentiality_priority") == "high":
                    adjustment["confidentiality"] = 1
                    reasoning.append("→ 機密性: +1段階 (高優先度)")
                
                if details.get("integrity_priority") == "highest":
                    adjustment["integrity"] = 2
                    reasoning.append("→ 完全性: +2段階 (最高優先度)")
                elif details.get("integrity_priority") == "high":
                    adjustment["integrity"] = 1
                    reasoning.append("→ 完全性: +1段階 (高優先度)")
                
                if details.get("availability_priority") == "highest":
                    adjustment["availability"] = 2
                    reasoning.append("→ 可用性: +2段階 (最高優先度)")
                elif details.get("availability_priority") == "high":
                    adjustment["availability"] = 1
                    reasoning.append("→ 可用性: +1段階 (高優先度)")
                
                return adjustment, reasoning
        
        reasoning.append("該当する特定資産分類なし → 調整なし")
        return {"confidentiality": 0, "integrity": 0, "availability": 0}, reasoning
    
    def _estimate_data_requirements_with_path(self, device_type: str, threat_name: str, data_types: List[str] = None) -> Tuple[Dict[str, str], List[str]]:
        """デバイスタイプと脅威名からデータ要求レベルを推定し、推論過程を記録"""
        if data_types is None:
            data_types = []
        reasoning = ["Step 3: データ要求レベルの推定"]
        
        # データタイプベースの調整（threat_extraction用）
        if "患者情報" in data_types:
            reasoning.append("患者個人識別情報 (PII) → 機密性: 最高")
            return {"confidentiality": "highest", "integrity": "high", "availability": "medium"}, reasoning
        
        safety_data = ["安全機能設定", "アラーム閾値", "治療計画"]
        for data in safety_data:
            if data in data_types:
                reasoning.append(f"安全性・リスク管理データ: {data} → I: 最高, A: 最高")
                return {"confidentiality": "medium", "integrity": "highest", "availability": "highest"}, reasoning
        
        # 安全性・有効性クリティカルなデータ
        for keyword in self.attack_patterns["life_critical_keywords"]:
            if keyword in device_type:
                reasoning.append(f"生命維持機器: '{keyword}' → 安全性・有効性クリティカル")
                reasoning.append("→ C:high, I:highest, A:highest")
                return {"confidentiality": "high", "integrity": "highest", "availability": "highest"}, reasoning
        
        # 診断・画像データ
        for keyword in self.attack_patterns["diagnostic_keywords"]:
            if keyword in device_type:
                reasoning.append(f"診断・画像機器: '{keyword}' → 診断精度クリティカル")
                reasoning.append("→ C:high, I:highest, A:high")
                return {"confidentiality": "high", "integrity": "highest", "availability": "high"}, reasoning
        
        # 情報システム
        for keyword in self.attack_patterns["info_system_keywords"]:
            if keyword in device_type:
                reasoning.append(f"医療情報システム: '{keyword}' → 情報セキュリティクリティカル")
                reasoning.append("→ C:highest, I:high, A:high")
                return {"confidentiality": "highest", "integrity": "high", "availability": "high"}, reasoning
        
        # デフォルト
        reasoning.append("一般的医療機器 → 標準的なデータ要求")
        reasoning.append("→ C:medium, I:high, A:medium")
        return {"confidentiality": "medium", "integrity": "high", "availability": "medium"}, reasoning
    
    def _apply_adjustments_with_path(self, base_impact: str, asset_adjustment: int, data_requirement: str, impact_type: str) -> Tuple[str, str]:
        """調整値を適用して最終影響度を決定し、推論過程を記録"""
        # 影響度の数値変換
        impact_values = {"N": 0, "L": 1, "H": 2}
        requirement_values = {"low": 0, "medium": 1, "high": 2, "highest": 3}
        
        base_value = impact_values[base_impact]
        requirement_value = requirement_values[data_requirement]
        
        # ベース影響度がNoneの場合は調整を行わない（攻撃に直接影響がない場合）
        if base_impact == "N":
            final_impact = "N"
            reasoning = f"{impact_type}調整: Base:{base_impact}(直接影響なし) → データ要求による調整をスキップ → 最終:{final_impact}"
        else:
            # 調整適用
            adjusted_value = min(base_value + asset_adjustment, 2)
            final_value = max(adjusted_value, min(requirement_value, 2))
            
            # 数値を影響度に変換
            value_to_impact = {0: "N", 1: "L", 2: "H"}
            final_impact = value_to_impact[final_value]
            
            # 推論文生成
            reasoning = f"{impact_type}調整: Base:{base_impact}(値:{base_value}) + 資産調整:{asset_adjustment} = {adjusted_value}, データ要求:{data_requirement}(値:{requirement_value}) → 最終:{final_impact}"
        
        return final_impact, reasoning
    
    def _apply_asset_adjustment_only_with_path(self, base_impact: str, asset_adjustment: int, impact_type: str) -> Tuple[str, str]:
        """資産調整のみを適用して最終影響度を決定し、推論過程を記録"""
        # 影響度の数値変換
        impact_values = {"N": 0, "L": 1, "H": 2}
        
        base_value = impact_values[base_impact]
        
        # ベース影響度がNoneの場合は調整を行わない
        if base_impact == "N":
            final_impact = "N"
            reasoning = f"{impact_type}調整: Base:{base_impact}(直接影響なし) → 最終:{final_impact}"
        else:
            # 資産調整のみ適用
            adjusted_value = min(base_value + asset_adjustment, 2)
            
            # 数値を影響度に変換
            value_to_impact = {0: "N", 1: "L", 2: "H"}
            final_impact = value_to_impact[adjusted_value]
            
            # 推論文生成
            reasoning = f"{impact_type}調整: Base:{base_impact}(値:{base_value}) + 資産調整:{asset_adjustment} → 最終:{final_impact}"
        
        return final_impact, reasoning