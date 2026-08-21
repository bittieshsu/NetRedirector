@echo off
REM ============================================================
REM 已由統一建置腳本 build.ps1 取代 (自動偵測 MSVC Build Tools)。
REM 本檔案保留為相容入口。
REM 用法: build.ps1              -> 僅編譯 DLL
REM       build.ps1 -Standalone  -> 編譯 DLL + Nuitka 目錄模式
REM       build.ps1 -Onefile     -> 編譯 DLL + Nuitka 單一 exe 模式
REM ============================================================
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0..\build.ps1" %*
pause
