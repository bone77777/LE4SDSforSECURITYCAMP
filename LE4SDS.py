import math

class HCASInferenceEngine:
    def __init__(self):
        # 重み（係数）の定義
        self.WEIGHTS = {
            "TRAFFIC_VOLUME": 0.6,      # 通信量の多さ
            "TI_IP_MATCH": 0.9,         # IP単位の完全一致（高解像度）
            "TI_SUBNET_MATCH": 0.15,     # サブネット単位の一致（低解像度）
            "TRUST_SIGNATURE": -0.85,   # デジタル署名の有効性（強力な負の重み）
            "TRUST_PARENT_PROC": -0.4,  # 正規の親プロセス（負の重み）
        }
        self.THRESHOLD = 0.8  # 自動遮断を実行する閾値 (80%)

    def calculate_risk(self, evidence):
        """
        階層的なコンテキスト解析に基づき、最終リスクスコアを算出する
        """
        print("--- 判定プロセス開始 ---")
        
        # 1. 通信振る舞いによるベースリスクの算定
        # 例: 1GB以上なら最大値、それ未満は比例（簡易モデル）
        volume_gb = evidence.get("traffic_volume_gb", 0)
        base_risk = min(1.0, volume_gb / 5.0) * self.WEIGHTS["TRAFFIC_VOLUME"]
        print(f"[Behavior] 通信量({volume_gb}GB): +{base_risk:.2f}")

        # 2. 脅威インテリジェンス(TI)の評価（解像度による動的重み付け）
        ti_score = 0
        if evidence.get("ti_match_type") == "IP":
            ti_score = 1.0 * self.WEIGHTS["TI_IP_MATCH"]
            print(f"[TI] IP一致(高解像度): +{ti_score:.2f}")
        elif evidence.get("ti_match_type") == "SUBNET":
            ti_score = 1.0 * self.WEIGHTS["TI_SUBNET_MATCH"]
            print(f"[TI] サブネット一致(低解像度): +{ti_score:.2f}")

        # 3. 信頼指標による相殺（負の重み付け）
        trust_offset = 0
        if evidence.get("is_signature_valid"):
            trust_offset += self.WEIGHTS["TRUST_SIGNATURE"]
            print(f"[Trust] 有効なデジタル署名を確認: {self.WEIGHTS['TRUST_SIGNATURE']}")
        
        if evidence.get("is_authorized_parent"):
            trust_offset += self.WEIGHTS["TRUST_PARENT_PROC"]
            print(f"[Trust] 正規の親プロセスを確認: {self.WEIGHTS['TRUST_PARENT_PROC']}")

        # 4. 最終スコアの算出（シグモイド関数等で0-1に正規化するのが一般的だが、今回は簡易化）
        # スコア = (リスク因子の合計) + (信頼因子の合計)
        # 信頼因子は負の値なので、リスクを「相殺」する
        raw_score = base_risk + ti_score + trust_offset
        
        # 0.0 ~ 1.0 の範囲にクランプ
        final_confidence = max(0.0, min(1.0, raw_score))
        
        return final_confidence

    def make_decision(self, score):
        print(f"\n最終確信度: {score:.2%}")
        if score >= self.THRESHOLD:
            return "【ACTION】 ネットワークを遮断し、アカウントを停止します（高リスク）"
        elif score >= 0.3:
            return "【ACTION】 アナリストへ通知します（低〜中リスク：要確認）"
        else:
            return "【ACTION】 正常な業務通信と判断し、ログを記録します（安全）"

# --- シミュレーション実行（今回のケース） ---

# 証拠データの入力（ログの内容を反映）
incident_data = {
    "traffic_volume_gb": 4.7,
    "ti_match_type": "SUBNET",     # IPそのものではなくサブネット一致
    "is_signature_valid": True,    # デジタル署名は有効
    "is_authorized_parent": True   # 親プロセスは正規（services.exe）
}

engine = HCASInferenceEngine()
final_score = engine.calculate_risk(incident_data)
decision = engine.make_decision(final_score)

print(decision)