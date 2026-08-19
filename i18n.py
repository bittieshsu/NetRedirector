import json
import os
import sys

DEFAULT_LANG = "zh_TW"
SUPPORTED_LANGS = (
    "zh_TW", "zh_CN", "en_US", "es_ES", "ko_KR", "ja_JP",
    "pt_BR", "fr_FR", "de_DE", "ru_RU", "it_IT", "vi_VN",
    "th_TH", "id_ID", "tr_TR", "pl_PL", "nl_NL",
)
LANG_NAMES = {
    "zh_TW": "繁體中文", "zh_CN": "简体中文", "en_US": "English",
    "es_ES": "Español", "ko_KR": "한국어", "ja_JP": "日本語",
    "pt_BR": "Português (BR)", "fr_FR": "Français", "de_DE": "Deutsch",
    "ru_RU": "Русский", "it_IT": "Italiano", "vi_VN": "Tiếng Việt",
    "th_TH": "ไทย", "id_ID": "Bahasa Indonesia", "tr_TR": "Türkçe",
    "pl_PL": "Polski", "nl_NL": "Nederlands",
}


def _find_locale_dir():
    candidates = []

    # 1. 模組所在位置 (開發模式 / Nuitka dist 目錄)
    candidates.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "locale"))

    # 2. 執行檔所在位置 (Nuitka / PyInstaller 打包後)
    exe_dir = os.path.dirname(os.path.abspath(sys.executable))
    candidates.append(os.path.join(exe_dir, "locale"))

    # 3. PyInstaller onefile 解壓目錄
    if getattr(sys, "_MEIPASS", None):
        candidates.append(os.path.join(sys._MEIPASS, "locale"))

    # 4. 目前工作目錄
    candidates.append(os.path.join(os.getcwd(), "locale"))

    for path in candidates:
        if os.path.isdir(path):
            return path
    return candidates[0]


class I18n:
    def __init__(self):
        self.locale_dir = _find_locale_dir()
        self.lang = DEFAULT_LANG
        self._table = {}

    def load(self, lang):
        self.lang = lang if lang in SUPPORTED_LANGS else DEFAULT_LANG
        self._table = {}
        path = os.path.join(self.locale_dir, f"{self.lang}.json")
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                self._table = data
        except Exception:
            self._table = {}

    def t(self, s):
        if not isinstance(s, str):
            return s
        return self._table.get(s, s)

    def lang_name(self, lang):
        return LANG_NAMES.get(lang, lang)


i18n = I18n()