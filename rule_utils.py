"""
rule_utils.py — 規則欄位處理輔助函式

從 IntegratedApp.py 抽出的純邏輯，無 GUI 依賴，可獨立單元測試。
"""

# 全形星號 U+FF0A（中文輸入法容易輸入）
FULLWIDTH_ASTERISK = "\uFF0A"
ASCII_ASTERISK = "*"


def normalize_wildcards(s):
    """將全形星號 (U+FF0A) 正規化為半形 '*'。

    中文輸入法輸入的 '＊' 逐位元組不等於 ASCII '*', 若直接存入 C 核心
    規則會被視為普通字串而非萬用字元，導致規則永不匹配、流量走直連。

    回傳 str | None: 傳入 None 回傳 None。
    """
    if s is None:
        return None
    return s.replace(FULLWIDTH_ASTERISK, ASCII_ASTERISK)


def normalize_rule_target(target):
    """正規化規則目標欄位 (進程名稱或 PID)。空字串回傳空字串。"""
    if target is None:
        return None
    return normalize_wildcards(target.strip())


def normalize_rule_pattern(field, default="*"):
    """正規化規則的 hosts/ports 欄位。空白時回傳 default ('*')。"""
    if field is None:
        return default
    field = normalize_wildcards(field.strip())
    return field or default
