# -*- coding: utf-8 -*-
"""設定自動存檔測試 — 「變更即存」與關機前落地。

以 Qt offscreen 平台執行，不顯示視窗、不需要管理員權限與 DLL。

回歸背景：設定變更過去只在程式「正常結束」時才寫入 config.json，
重新開機或強制結束會整批遺失（使用者回報「重開機後回到預設」）。
"""
import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtTest import QTest  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

import config_store  # noqa: E402
import tabs_hub  # noqa: E402
from autosave import AutoSaveMixin, SaveScheduler  # noqa: E402
from tabs_hub import HubTabMixin  # noqa: E402
from tabs_proxies import ProxiesTabMixin  # noqa: E402
from tabs_rules import RulesTabMixin  # noqa: E402


def _app():
    return QApplication.instance() or QApplication([])


class _Recorder:
    """記錄 request / flush 呼叫的假排程器。"""

    def __init__(self):
        self.requests = []
        self.flushes = []

    def request(self, delay_ms=None):
        self.requests.append(delay_ms)

    def flush(self, force=False):
        self.flushes.append(force)
        return True


# ------------------------------------------------------------ SaveScheduler

def test_flush_without_pending_does_nothing():
    _app()
    calls = []
    sched = SaveScheduler(lambda: calls.append(1), delay_ms=10)
    assert sched.flush() is False
    assert calls == []


def test_flush_force_writes_even_without_pending():
    """關機前寧可多寫一次，也不要漏掉最後的變更。"""
    _app()
    calls = []
    sched = SaveScheduler(lambda: calls.append(1), delay_ms=10)
    assert sched.flush(force=True) is True
    assert calls == [1]


def test_requests_are_coalesced_into_one_write():
    _app()
    calls = []
    sched = SaveScheduler(lambda: calls.append(1), delay_ms=10)
    sched.request()
    sched.request()
    assert sched.pending() is True
    assert sched.flush() is True
    assert calls == [1]
    assert sched.pending() is False


def test_cancel_drops_pending_write():
    _app()
    calls = []
    sched = SaveScheduler(lambda: calls.append(1), delay_ms=10)
    sched.request()
    sched.cancel()
    assert sched.pending() is False
    assert sched.flush() is False
    assert calls == []


def test_timer_writes_without_explicit_flush():
    _app()
    calls = []
    sched = SaveScheduler(lambda: calls.append(1), delay_ms=10)
    sched.request()
    QTest.qWait(200)
    assert calls == [1]


def test_change_is_persisted_to_disk_after_delay(tmp_path):
    """端到端：變更 → 延遲 → 設定檔真的落地。

    這是回報「重新開機後設定回到預設」的正式回歸測試：只要有人在變更後
    排程存檔，檔案就必須在沒有關閉程式的情況下出現。
    """
    _app()
    target = os.path.join(str(tmp_path), "config.json")

    class _Host(AutoSaveMixin):
        def __init__(self):
            self._save_scheduler = SaveScheduler(self._save, delay_ms=10)

        def _save(self):
            data = {"rules": [{"target": "g.exe"}]}
            config_store.save_config_file(target, data)

    host = _Host()
    host._request_save()
    assert not os.path.exists(target)        # 尚未到寫檔時間
    QTest.qWait(200)
    assert os.path.exists(target)            # 程式仍開著，設定已經落地
    saved = config_store.load_config_file(target)
    assert saved["rules"][0]["target"] == "g.exe"


# ------------------------------------------------------------ AutoSaveMixin

def test_mixin_request_save_is_noop_without_scheduler():
    class _Host(AutoSaveMixin):
        pass

    _Host()._request_save()  # 只有 mixin 的替身不應拋例外


def test_mixin_request_save_forwards_delay():
    class _Host(AutoSaveMixin):
        def __init__(self):
            self._save_scheduler = _Recorder()

    host = _Host()
    host._request_save()
    host._request_save(50)
    assert host._save_scheduler.requests == [None, 50]


# ------------------------------------------------------------ 假元件

class _CheckItem:
    def __init__(self, checked):
        self._checked = checked

    def checkState(self):
        return (Qt.CheckState.Checked if self._checked
                else Qt.CheckState.Unchecked)

    def setCheckState(self, state):
        self._checked = (state == Qt.CheckState.Checked)


class _TextItem:
    def __init__(self, text):
        self._text = text

    def text(self):
        return self._text


class _Table:
    """以 {(row, col): item} 模擬 QTableWidget.item()。"""

    def __init__(self, items):
        self._items = items

    def item(self, row, col):
        return self._items.get((row, col))

    def rowCount(self):
        return 1 + max((r for r, _c in self._items), default=-1)


class _FakeLib:
    def NetRedirector_DeleteProxyConfig(self, pid):
        pass


class _Bridge:
    def __init__(self):
        self.lib = _FakeLib()

    def delete_rule(self, rid):
        pass

    def add_rule_ex(self, *args):
        return 1


class _FakeTable:
    def __init__(self, row):
        self._row = row

    def currentRow(self):
        return self._row


class _ProxyCoreStub:
    """避免測試真的去停/啟 relay 服務。"""

    class _RouteManager:
        def update_port_binding(self, port, interfaces):
            pass

    class _ServerController:
        def stop_port(self, port):
            return True

        def start_port(self, port):
            return True

    def __init__(self):
        self.route_manager = self._RouteManager()
        self.server_controller = self._ServerController()


# ------------------------------------------------------------ Hub 分頁

class _HubStub(HubTabMixin):
    def __init__(self):
        self._save_scheduler = _Recorder()
        self.port_config = {}
        self.current_interfaces = {}
        self.hub_proxy_map = {}
        self.selected_hub_port = 30678
        self.bridge = _Bridge()
        self.table_hub = None

    def t(self, text):
        return text

    def append_log(self, message):
        pass

    def sync_hub_proxy(self, port):
        pass

    def refresh_hub_table(self):
        pass

    def refresh_proxy_combobox(self):
        pass


class _Spin:
    def __init__(self, value):
        self._value = value

    def value(self):
        return self._value

    def setValue(self, value):
        self._value = value


class _PortList:
    def __init__(self, items=()):
        self._items = [i if hasattr(i, "text") else _TextItem(i)
                       for i in items]

    def addItem(self, text):
        self._items.append(_TextItem(text))

    def selectedItems(self):
        return list(self._items)

    def currentItem(self):
        return self._items[0] if self._items else None

    def row(self, item):
        return self._items.index(item)

    def takeItem(self, row):
        self._items.pop(row)


def _hub_stub(monkeypatch, bound=()):
    _app()
    monkeypatch.setattr(tabs_hub, "proxy_core", _ProxyCoreStub())
    stub = _HubStub()
    stub.port_config[30678] = list(bound)
    stub.spin_hub_port = _Spin(30678)
    stub.list_hub_ports = _PortList()
    return stub


def test_hub_binding_click_requests_save(monkeypatch):
    stub = _hub_stub(monkeypatch)
    stub.table_hub = _Table({(0, 0): _CheckItem(False),
                             (0, 1): _TextItem("VPN-A")})
    stub.on_hub_table_click(0, 1)
    assert stub.port_config[30678] == ["VPN-A"]
    assert len(stub._save_scheduler.requests) == 1


def test_hub_select_all_requests_save(monkeypatch):
    stub = _hub_stub(monkeypatch)
    stub.table_hub = _Table({(0, 0): _CheckItem(False),
                             (0, 1): _TextItem("VPN-A")})
    stub.on_hub_select_all_visible()
    assert stub.port_config[30678] == ["VPN-A"]
    assert len(stub._save_scheduler.requests) == 1


def test_hub_add_port_requests_save(monkeypatch):
    stub = _hub_stub(monkeypatch)
    stub.spin_hub_port = _Spin(31000)      # 30678 已被 _hub_stub 佔用
    stub.add_hub_port()
    assert 31000 in stub.port_config
    assert len(stub._save_scheduler.requests) == 1


def test_hub_del_port_requests_save(monkeypatch):
    stub = _hub_stub(monkeypatch, bound=["VPN-A"])
    stub.list_hub_ports = _PortList(["30678"])
    stub.del_hub_port()
    assert 30678 not in stub.port_config
    assert len(stub._save_scheduler.requests) == 1


# ------------------------------------------------------------ 規則分頁

class _RulesStub(RulesTabMixin):
    def __init__(self):
        self._save_scheduler = _Recorder()
        self.rules = []
        self.bridge = _Bridge()

    def t(self, text):
        return text

    def append_log(self, message):
        pass

    def refresh_rules_table(self):
        pass


def test_toggle_rule_enabled_requests_save():
    _app()
    stub = _RulesStub()
    rule = {"id": 5, "enabled": True, "type": "Name", "target": "game.exe",
            "action_key": 0, "proxy_id": 0}
    stub.toggle_rule_enabled(rule, False)
    assert rule["enabled"] is False
    assert len(stub._save_scheduler.requests) == 1


# ------------------------------------------------------------ 代理分頁

class _ProxiesStub(ProxiesTabMixin):
    def __init__(self):
        self._save_scheduler = _Recorder()
        self.custom_proxies = [{"id": 3, "name": "P1"}]
        self.bridge = _Bridge()
        self.table_custom_proxies = _FakeTable(0)

    def t(self, text):
        return text

    def append_log(self, message):
        pass

    def refresh_custom_proxy_table(self):
        pass

    def refresh_proxy_combobox(self):
        pass

    def reapply_all_rules(self, only_proxy_id=None):
        pass


def test_del_custom_proxy_requests_save():
    _app()
    stub = _ProxiesStub()
    stub.del_custom_proxy()
    assert stub.custom_proxies == []
    assert len(stub._save_scheduler.requests) == 1


# ------------------------------------------------------------ 主視窗接線

def test_mainwindow_has_session_end_hooks():
    """關機路徑與載入期暫停存檔的入口必須存在。"""
    from IntegratedApp import MainWindow

    for name in ("_on_commit_data_request", "_on_about_to_quit",
                 "_flush_save", "_apply_loaded_config"):
        assert callable(getattr(MainWindow, name, None)), name


def test_commit_data_request_flushes_forced():
    """模擬 Windows 關機：commitDataRequest 必須「強制」寫檔。"""
    from IntegratedApp import MainWindow

    calls = []

    class _Fake:
        def _flush_save(self, force=False):
            calls.append(force)

    MainWindow._on_commit_data_request(_Fake())
    assert calls == [True]


def test_about_to_quit_flushes_pending_only():
    from IntegratedApp import MainWindow

    calls = []

    class _Fake:
        def _flush_save(self, force=False):
            calls.append(force)

    MainWindow._on_about_to_quit(_Fake())
    assert calls == [False]


def test_request_save_skipped_while_loading_config():
    """載入設定期間不得排程存檔，否則會把剛讀到的設定再寫回去。"""
    from IntegratedApp import MainWindow

    rec = _Recorder()

    class _Fake:
        _loading_config = True
        _shutdown_done = False
        _save_scheduler = rec

    MainWindow._request_save(_Fake())
    assert rec.requests == []
