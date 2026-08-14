import json
import os

DEFAULT_LANG = "zh_TW"
SUPPORTED_LANGS = ("zh_TW", "en_US")
LANG_NAMES = {"zh_TW": "繁體中文", "en_US": "English"}


class I18n:
    def __init__(self):
        self.locale_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "locale")
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
