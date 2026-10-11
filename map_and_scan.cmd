@echo off
REM ============================================================
REM  CODM ESP — one-shot: map the kernel driver, then scan.
REM  Run as Administrator from a normal (non-VBS) console.
REM ============================================================
setlocal

set ROOT=%~dp0
set TOOLS=%ROOT%tools

if not exist "%TOOLS%\kdu.exe" (
    echo [x] tools\kdu.exe missing - build it via .github\workflows\build-kdu.yml
    exit /b 1
)
if not exist "%ROOT%km.sys" (
    echo [x] km.sys missing - build it via .github\workflows\build-driver.yml
    exit /b 1
)

echo === Mapping km.sys (provider 54 / NeacSafe64) ===
pushd "%TOOLS%"
kdu.exe -map "%ROOT%km.sys" -prv 54
set RC=%ERRORLEVEL%
popd
if not "%RC%"=="0" (
    echo [x] kdu failed with %RC%
    exit /b %RC%
)

echo.
echo === Driver mapped. Sanity check ===
"%ROOT%test_read.exe"
echo.
echo === Usage ===
echo   scanner.exe modules              list loaded modules
echo   scanner.exe meta                  full scan + dump global-metadata
echo   scanner.exe meta --deep           also scan 16-64 GB range (slow)
echo   scanner.exe scan --range 1a0000000:1b0000000
echo   scanner.exe dump ^<addr^> ^<size^> file.bin
echo   scanner.exe read ^<addr^> 64
echo   scanner.exe pe GameAssembly.dll out\ga.dll