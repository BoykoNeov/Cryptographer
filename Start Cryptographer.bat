@echo off
setlocal enabledelayedexpansion
REM ============================================================
REM  Cryptographer launcher — double-click to run the app.
REM  Starts the Vite dev server and opens it in your browser.
REM
REM  Port handling: other locally-running dev tools (often other
REM  Vite/Claude-derived apps) grab the default 5173, and the old
REM  launcher blindly opened the browser at 5173 — landing on the
REM  wrong app. So we now probe a list of candidate ports, bind
REM  the first FREE one (pinned with --strictPort so Vite can't
REM  silently drift to yet another port), and open the browser at
REM  exactly that port. If every candidate is busy, we free the
REM  first one by killing whatever is listening on it.
REM ============================================================

cd /d "%~dp0"

echo Starting Cryptographer...
echo.

REM Install dependencies on first run (node_modules missing).
if not exist "node_modules" (
    echo First run: installing dependencies. This may take a minute...
    call npm install
    if errorlevel 1 (
        echo.
        echo npm install failed. Is Node.js installed?  https://nodejs.org
        pause
        exit /b 1
    )
)

REM Candidate ports, tried left to right. 5173 is Vite's default;
REM the rest are fallbacks that are unlikely to collide.
set "PORTS=5173 5174 5175 5180 5190"
set "CHOSEN="

for %%P in (%PORTS%) do (
    if not defined CHOSEN (
        call :isfree %%P && set "CHOSEN=%%P"
    )
)

if not defined CHOSEN (
    REM Every candidate is occupied — reclaim the first one in the
    REM list by terminating its listener, then use it.
    for /f "tokens=1" %%A in ("%PORTS%") do set "FIRST=%%A"
    echo All candidate ports are busy. Freeing port !FIRST!...
    call :killport !FIRST!
    set "CHOSEN=!FIRST!"
)

echo Using port !CHOSEN!.
echo.

REM Give Vite a moment to boot, then open the browser to the port
REM we actually bound (not a hardcoded guess).
start "" cmd /c "timeout /t 3 >nul & start http://localhost:!CHOSEN!"

REM Run the dev server in this window. --strictPort makes Vite fail
REM loudly instead of drifting to another port if this one races.
REM Close the window (or Ctrl+C) to stop.
call npm run dev -- --port !CHOSEN! --strictPort

pause
exit /b

REM ------------------------------------------------------------
REM :isfree PORT  — exit 0 if the port has no LISTENING socket,
REM                 exit 1 if something is already listening.
REM /C:":PORT " uses a literal search (with the trailing space so
REM ":5173 " never matches ":51730 "); without /C findstr would
REM split on the space into an OR that also matches an empty
REM pattern (i.e. every line).
REM ------------------------------------------------------------
:isfree
netstat -ano | findstr /C:":%1 " | findstr LISTENING >nul 2>&1
if errorlevel 1 (exit /b 0) else (exit /b 1)

REM ------------------------------------------------------------
REM :killport PORT — kill the PID(s) LISTENING on PORT. In netstat
REM -ano output the PID is the 5th whitespace token.
REM ------------------------------------------------------------
:killport
for /f "tokens=5" %%K in ('netstat -ano ^| findstr /C:":%1 " ^| findstr LISTENING') do (
    echo Killing PID %%K holding port %1
    taskkill /F /PID %%K >nul 2>&1
)
exit /b
