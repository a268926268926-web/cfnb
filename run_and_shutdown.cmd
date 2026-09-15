@echo off
rem cfnb scheduled run wrapper v2 (2026-09-13)
rem usage: run_and_shutdown.cmd [--shutdown]
rem   --shutdown: power off after run, BUT only if PC was cold-started by the task.
rem   If a user session already exists (PC was awake before run), skip shutdown.
cd /d "C:\Users\Galbrena\.zcode\workspace\default\cfnb"
echo [%date% %time%] cfnb scheduled run start >> "%~dp0scheduled_run.log"

rem detect user session: explorer.exe running = PC was already awake
set WAS_AWAKE=0
tasklist 2>nul | findstr /C:"explorer.exe" >nul
if not errorlevel 1 set WAS_AWAKE=1
echo [%date% %time%] was_awake=%WAS_AWAKE% >> "%~dp0scheduled_run.log"
rem check if sing-box is running (warn if active, does not block)
tasklist 2>nul | findstr /C:"sing-box.exe" >nul
if not errorlevel 1 echo [%date% %time%] WARN: sing-box process detected, results may be proxied >> "%~dp0scheduled_run.log"

"C:\Users\Galbrena\AppData\Local\Programs\Python\Python313\python.exe" "C:\Users\Galbrena\.zcode\workspace\default\cfnb\fetch_sources.py" >> "%~dp0scheduled_run.log" 2>&1
"C:\Users\Galbrena\AppData\Local\Programs\Python\Python313\python.exe" "C:\Users\Galbrena\.zcode\workspace\default\cfnb\main.py" >> "%~dp0scheduled_run.log" 2>&1
echo [%date% %time%] cfnb run end, exit=%errorlevel% >> "%~dp0scheduled_run.log"

if "%~1"=="--shutdown" (
    if "%WAS_AWAKE%"=="1" (
        echo [%date% %time%] PC was already awake, skip shutdown >> "%~dp0scheduled_run.log"
    ) else (
        echo [%date% %time%] auto hibernate in 60s >> "%~dp0scheduled_run.log"
        shutdown /h /t 60 /c "cfnb scheduled run finished, hibernating"
    )
)
