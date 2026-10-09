# -*- coding: utf-8 -*-
"""設定自動存檔排程 — 「變更即存」與關機前落地。

為什麼需要這個模組？
    設定的變更 (自訂代理、規則、Hub 綁定、勾選項) 過去只在程式「正常結束」
    (closeEvent → _perform_shutdown) 時才寫入 config.json。因此重新開機、
    工作管理員強制結束、當機、斷電都會整批遺失 —— 使用者看到的是「重新開機
    後設定回到預設」。改為變更後延遲寫檔，並在工作階段結束前強制落地。

設計：
    - ``SaveScheduler`` 只負責「把短時間內多次變更合併成一次寫檔」，實際的
      序列化與檔案 I/O 由呼叫端以 callback 注入 (方便測試，不依賴 GUI)。
    - ``AutoSaveMixin`` 讓各分頁 mixin 以 ``self._request_save()`` 請求存檔，
      不必知道排程細節；測試替身沒有注入 scheduler 時自動退化成 no-op。
"""

from PySide6.QtCore import QTimer

# 變更後延遲寫檔的毫秒數：夠短讓使用者無感，夠長讓連續操作合併成一次 I/O。
DEFAULT_DELAY_MS = 800


class SaveScheduler:
    """把短時間內多次的變更合併成一次寫檔。"""

    def __init__(self, save_cb, delay_ms=DEFAULT_DELAY_MS, parent=None):
        self._save_cb = save_cb
        self._delay_ms = int(delay_ms)
        self._timer = QTimer(parent)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self._on_timeout)

    def _on_timeout(self):
        self._save_cb()

    def request(self, delay_ms=None):
        """請求延遲寫檔；連續呼叫會重新計時，最終只寫一次。"""
        delay = self._delay_ms if delay_ms is None else int(delay_ms)
        self._timer.start(delay)

    def cancel(self):
        """取消尚未觸發的寫檔。"""
        self._timer.stop()

    def pending(self):
        """是否有已排程但尚未寫入的變更。"""
        return self._timer.isActive()

    def flush(self, force=False):
        """立刻寫檔；回傳是否真的寫了。

        ``force=True`` 時即使沒有待寫變更也寫一次，用於「程序即將被終止」的
        場合 (關機/登出)：寧可多寫一次，也不要漏掉最後的變更。
        """
        was_pending = self.pending()
        self.cancel()
        if not was_pending and not force:
            return False
        self._save_cb()
        return True


class AutoSaveMixin:
    """分頁 mixin 請求存檔的入口。

    ``_save_scheduler`` 由主視窗注入；只有 mixin 的測試替身沒有它，
    此時 ``_request_save()`` 為 no-op，不會讓既有測試需要額外的 mock。
    """

    def _request_save(self, delay_ms=None):
        scheduler = getattr(self, "_save_scheduler", None)
        if scheduler is not None:
            scheduler.request(delay_ms)
