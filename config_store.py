"""
config_store.py — 設定序列化與檔案 I/O (自 IntegratedApp.py 抽出)

純邏輯、無 GUI 依賴：代理密碼以 DPAPI 加密存放、規則保存 UI 辨識字串。
"""

import json
import os

import secure_config


def build_config_data(lang, ping_target, hubs, custom_proxies, rules):
    """把執行期狀態序列化為 config.json 結構。

    - Proxy: 移除動態數據 (latency/ID)，密碼以 DPAPI 加密
    - Rules: 保存 Proxy 的 UI 辨識字串 (例如 "[Custom] MyVPN") 而非動態 ID
    """
    config_data = {
        "lang": lang,
        "ping_target": ping_target,
        "hubs": hubs or {},
        "proxies": [],
        "rules": [],
    }

    for p in custom_proxies:
        config_data["proxies"].append({
            "name": p['name'],
            "type": p['type'],
            "ip": p['ip'],
            "port": p['port'],
            "user": p['user'],
            "pass": secure_config.encrypt_password(p['pass']),
        })

    for r in rules:
        config_data["rules"].append({
            "type": r['type'],
            "target": r['target'],
            "hosts": r.get('hosts', '*'),
            "ports": r.get('ports', '*'),
            "proto": r.get('proto', 'BOTH'),
            "action": r['action'],
            "action_key": r.get('action_key'),
            "proxy_text": r['proxy'],
        })

    return config_data


def save_config_file(path, data):
    """寫入設定檔。成功回傳 None，失敗回傳錯誤訊息字串。"""
    try:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return None
    except Exception as e:
        return str(e)


def load_config_file(path):
    """讀取設定檔。檔案不存在或解析失敗回傳 None。"""
    if not os.path.exists(path):
        return None
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return None
