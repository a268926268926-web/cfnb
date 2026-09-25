@echo off
setlocal
chcp 65001 >nul
rem cfnb scheduled wrapper v5 (2026-09-25): truthful exit codes and fresh-pool gate.
rem usage: run_and_shutdown.cmd [--shutdown]
rem   --shutdown: power off after run, BUT only if PC was cold-started by the task.
rem   If a user session already exists (PC was awake before run), skip shutdown.
rem v3: added environment self-check gate. If traffic is proxied (TUN / fakeip DNS),
rem     the run is SKIPPED and ip.txt is left untouched -- proxied rounds produce
rem     bogus "elite" IPs that phones cannot reach (2026-09-15 incident).
rem Never stop/restart the user's proxy service from this task.
cd /d "%~dp0"
if errorlevel 1 exit /b 1
echo [%date% %time%] cfnb scheduled run start >> "%~dp0scheduled_run.log"

rem detect user session: explorer.exe running = PC was already awake
set WAS_AWAKE=0
tasklist 2>nul | findstr /C:"explorer.exe" >nul
if not errorlevel 1 set WAS_AWAKE=1
echo [%date% %time%] was_awake=%WAS_AWAKE% >> "%~dp0scheduled_run.log"

rem check if sing-box is running (warn only, the real gate is the env check below)
tasklist 2>nul | findstr /C:"sing-box.exe" >nul
if not errorlevel 1 echo [%date% %time%] WARN: sing-box process detected >> "%~dp0scheduled_run.log"

set PY=C:\Users\Galbrena\AppData\Local\Programs\Python\Python313\python.exe
set RC=0
rem Force UTF-8: redirected stdout otherwise defaults to GBK and mangles Chinese output
set PYTHONIOENCODING=utf-8
set PYTHONUTF8=1

rem ================= TUN pause: TRIED AND REVERTED (2026-09-21 20:16) =================
rem Stopping the service DID release the TUN and made the measurement real, but the
rem restore is NOT reliable: the TUN is created by the GUI+service pair, and net stop
rem also takes the GUI down. net start brings the service back -- it even reports
rem RUNNING -- while the TUN adapter stays absent, so the user's proxy is dead while
rem every health check says healthy. Only relaunching the GUI app fixes it, and a
rem SYSTEM task cannot do that properly (it would start in session 0).
rem Evidence: 19:47 stop/start restored the TUN (GUI still alive); the 20:10 stop/start
rem left the service RUNNING with no TUN until the user reopened the app manually.
rem So the scheduled task must NOT touch the service. If the env gate fails, we skip.
rem The run needs a proxy-off window; that is a user decision (see proxy_watchdog.log
rem and the task notes). Do not re-add the stop without solving the GUI problem.

:run
rem ---- gate: direct-link self-check (fakeip DNS / Cloudflare egress = polluted) ----
rem This gate stays the authority: if traffic is hijacked, it fails and we skip
rem instead of writing a hijacked pool.
"%PY%" "%~dp0e2e_test.py" env >> "%~dp0scheduled_run.log" 2>&1
if errorlevel 1 goto :polluted

rem fetch_sources has its own hijack check (colo probe, median TCP<10ms => refuse)
"%PY%" "%~dp0fetch_sources.py" >> "%~dp0scheduled_run.log" 2>&1
if errorlevel 1 goto :fetchfail

"%PY%" "%~dp0main.py" >> "%~dp0scheduled_run.log" 2>&1
set RC=%errorlevel%
echo [%date% %time%] cfnb run end, exit=%RC% >> "%~dp0scheduled_run.log"
rem ---- sync the pool into the self-built preferred domain (DNSHE) ----
rem main: 0=fresh pool published, 5=fresh pool but GitHub failed.
rem Both may sync DNS; 2/4/other codes must never sync the previous round's pool.
if not "%RC%"=="0" if not "%RC%"=="5" goto :power
if not exist ip.txt goto :dnsfail
if not exist "%~dp0dnshe.env" (
    echo [%date% %time%] WARN: dnshe.env missing, cf.codm.l.cd not synced >> "%~dp0scheduled_run.log"
    goto :dnsfail
)
set "DNSHE_KEY="
set "DNSHE_SECRET="
for /f "usebackq tokens=1,* delims==" %%a in ("%~dp0dnshe.env") do (
    if "%%a"=="DNSHE_KEY" set "DNSHE_KEY=%%b"
    if "%%a"=="DNSHE_SECRET" set "DNSHE_SECRET=%%b"
)
if not defined DNSHE_KEY goto :dnsfail
if not defined DNSHE_SECRET goto :dnsfail
echo [%date% %time%] syncing cf.codm.l.cd A records from fresh ip.txt >> "%~dp0scheduled_run.log"
"%PY%" "%~dp0dnshe_sync.py" --apply >> "%~dp0scheduled_run.log" 2>&1
if errorlevel 1 goto :dnsfail
goto :power

:dnsfail
echo [%date% %time%] ERROR: fresh pool DNS sync failed or credentials missing >> "%~dp0scheduled_run.log"
if "%RC%"=="5" (set RC=7) else (set RC=6)
goto :power

:polluted
echo [%date% %time%] SKIP: environment polluted (fakeip DNS or proxied egress), ip.txt NOT overwritten >> "%~dp0scheduled_run.log"
set RC=2
goto :power

:fetchfail
echo [%date% %time%] SKIP: fetch_sources failed (likely hijacked link, see log), main.py NOT run >> "%~dp0scheduled_run.log"
set RC=3

:power
echo [%date% %time%] pipeline exit=%RC% [0=OK 1=uncaught-crash 2=environment 3=sources 4=no-pool 5=GitHub 6=DNS 7=GitHub+DNS] >> "%~dp0scheduled_run.log"
if "%~1"=="--shutdown" (
    if "%WAS_AWAKE%"=="1" (
        echo [%date% %time%] PC was already awake, skip shutdown >> "%~dp0scheduled_run.log"
    ) else (
        echo [%date% %time%] auto hibernate in 60s >> "%~dp0scheduled_run.log"
        shutdown /h /t 60 /c "cfnb scheduled run finished, hibernating"
    )
)
rem Non-zero exit code makes the skip visible instead of a fake success
rem (2026-09-21: silent skip for 5 days while LastTaskResult stayed 0)
exit /b %RC%
