# -*- coding: utf-8 -*-
"""process_utils 單元測試 — 進程列舉結果格式與去重。"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import process_utils


def test_list_processes_returns_tuples():
    result = process_utils.list_processes()
    assert isinstance(result, list)
    for entry in result:
        assert isinstance(entry, tuple) and len(entry) == 2
        name, pid = entry
        assert isinstance(name, str) and name
        assert isinstance(pid, int) and pid > 0


def test_list_processes_deduplicates_names():
    result = process_utils.list_processes()
    names = [name.lower() for name, _pid in result]
    assert len(names) == len(set(names)), "同名進程應只保留一筆"


def test_list_processes_sorted_case_insensitively():
    result = process_utils.list_processes()
    names = [name.lower() for name, _pid in result]
    assert names == sorted(names)


def test_list_process_names_matches_processes():
    assert process_utils.list_process_names() == [
        name for name, _pid in process_utils.list_processes()]


def test_non_windows_returns_empty(monkeypatch):
    monkeypatch.setattr(process_utils.sys, "platform", "linux")
    assert process_utils.list_processes() == []
