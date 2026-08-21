# -*- coding: utf-8 -*-
"""rule_utils 單元測試 — 全形星號正規化與規則欄位處理"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rule_utils import (
    FULLWIDTH_ASTERISK,
    normalize_wildcards,
    normalize_rule_target,
    normalize_rule_pattern,
)


def test_fullwidth_asterisk_is_ff0a():
    assert FULLWIDTH_ASTERISK == "\uFF0A"
    assert FULLWIDTH_ASTERISK != "*"  # 逐位元組不同


def test_normalize_wildcards_replaces_fullwidth():
    assert normalize_wildcards("＊") == "*"
    assert normalize_wildcards("chrome.exe＊") == "chrome.exe*"
    assert normalize_wildcards("＊.exe;＊") == "*.exe;*"


def test_normalize_wildcards_ascii_unchanged():
    assert normalize_wildcards("*") == "*"
    assert normalize_wildcards("fire*.exe") == "fire*.exe"


def test_normalize_wildcards_none():
    assert normalize_wildcards(None) is None


def test_normalize_wildcards_empty():
    assert normalize_wildcards("") == ""


def test_normalize_rule_target_strips_and_normalizes():
    assert normalize_rule_target("  ＊  ") == "*"
    assert normalize_rule_target("Game.exe") == "Game.exe"
    assert normalize_rule_target("") == ""


def test_normalize_rule_pattern_defaults():
    assert normalize_rule_pattern("") == "*"
    assert normalize_rule_pattern(None) == "*"
    assert normalize_rule_pattern("  ") == "*"
    assert normalize_rule_pattern("＊") == "*"
    assert normalize_rule_pattern("80;443") == "80;443"
    assert normalize_rule_pattern(" 80;443 ") == "80;443"


def test_normalize_rule_pattern_keeps_explicit():
    assert normalize_rule_pattern("1.2.3.4") == "1.2.3.4"
