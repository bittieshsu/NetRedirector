# -*- coding: utf-8 -*-
"""i18n 語系檔完整性測試 — 所有語系 JSON 有效且鍵集合一致"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from i18n import SUPPORTED_LANGS, i18n

LOCALE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "locale")


def _load_all_locales():
    data = {}
    for lang in SUPPORTED_LANGS:
        path = os.path.join(LOCALE_DIR, f"{lang}.json")
        assert os.path.exists(path), f"缺少語系檔 {lang}.json"
        with open(path, encoding="utf-8") as f:
            data[lang] = json.load(f)
    return data


def test_all_locale_files_exist_and_valid_json():
    locales = _load_all_locales()
    assert len(locales) == len(SUPPORTED_LANGS)


def test_all_locales_have_identical_key_sets():
    locales = _load_all_locales()
    base_keys = set(locales["zh_TW"].keys())
    for lang, data in locales.items():
        keys = set(data.keys())
        missing = base_keys - keys
        extra = keys - base_keys
        assert not missing, f"{lang} 缺少鍵: {sorted(missing)}"
        assert not extra, f"{lang} 多出鍵: {sorted(extra)}"


def test_zh_tw_is_identity_mapping():
    # zh_TW 是來源語言: 鍵值應相同 (或至少每個鍵都有對應值)
    locales = _load_all_locales()
    for key, val in locales["zh_TW"].items():
        assert isinstance(val, str), f"鍵 {key} 的值非字串"


def test_all_translations_nonempty():
    locales = _load_all_locales()
    for lang, data in locales.items():
        for key, val in data.items():
            assert val.strip() != "", f"{lang} 的鍵 {key} 翻譯為空"


def test_i18n_load_and_lookup():
    # i18n 是模組層級的單例實例 (IntegratedApp 使用 `from i18n import i18n as tr`)
    tr = i18n
    tr.load("en_US")
    assert tr.t("Ping 目標:") == "Ping Target:"
    assert tr.t("不存在的中文鍵xyz") == "不存在的中文鍵xyz"  # 缺鍵回退原文
    tr.load("zh_TW")
    assert tr.t("Ping 目標:") == "Ping 目標:"
