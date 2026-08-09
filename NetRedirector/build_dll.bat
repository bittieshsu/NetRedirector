@echo off
echo Compiling NetRedirector.dll...

REM 確保你使用的是 64-bit 編譯環境
REM /DNETREDIRECTOR_EXPORTS 告訴編譯器我們正在生成 DLL，所以要導出函數

cl /LD /DNETREDIRECTOR_EXPORTS NetRedirector.c NR_Core.c NR_Protocol.c NR_RuleEngine.c NR_State.c NR_Utils.c /Fe:NetRedirector.dll /I. windivert.lib User32.lib Advapi32.lib Ws2_32.lib Iphlpapi.lib

if %errorlevel% neq 0 (
    echo Compilation Failed!
    pause
    exit /b %errorlevel%
)

echo Compilation Successful!
echo Ensure windivert.dll and windivert64.sys are in the same folder.
pause