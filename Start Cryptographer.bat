@echo off
setlocal enabledelayedexpansion
REM ============================================================
REM  Cryptographer launcher - double-click to run the app.
REM
REM  Reuses a dev server that is already serving THIS project if
REM  one is running, and starts a new one only otherwise.
REM
REM  Why: Vite does not fail when its port is busy - it climbs to
REM  the next free port - so the old "find a free port and bind
REM  it" launcher quietly left another server running on every
REM  double-click, sixteen deep across 5173-5190.
REM
REM  And a port does not tell you WHOSE server it is: several Vite
REM  projects on this machine climb past each other, so 5173 is
REM  very often a different app. scripts\find-dev-server.mjs
REM  therefore identifies our server by what it SERVES (index.html's
REM  <title>) and we reuse only a real match. Nothing here probes
REM  for a free port, and nothing here kills anything: taking a
REM  port from whatever is holding it is how you murder someone's
REM  live work in another project.
REM ============================================================

cd /d "%~dp0"

REM Ask before installing: the reuse path needs no dependencies, so
REM even a half-set-up checkout can hop onto a running server.
REM
REM `set "URL="` first so a stale value from the environment cannot
REM leak in and fake a match. `2^>nul` escapes the redirect so it
REM applies to node rather than to the for. The detector prints the
REM URL on stdout and nothing else, so a captured line IS the answer.
set "URL="
for /f "usebackq delims=" %%u in (`node "scripts\find-dev-server.mjs" 2^>nul`) do set "URL=%%u"

if defined URL (
    echo Cryptographer is already running at !URL!
    echo Opening it in your browser.
    echo.
    echo   The running server reads your code from disk on every request,
    echo   so it is already serving your latest edits. The one exception is
    echo   vite.config.ts - if you changed that, close the old server's
    echo   window and run this launcher again to start fresh.
    REM `start` reads a lone quoted argument as the window title, so the
    REM empty "" title is required or the URL is swallowed as one.
    start "" "!URL!"
    exit /b
)

REM Nothing of ours is running, so we start one.

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

echo Starting Cryptographer...
echo.

REM No port probe here, on purpose. Vite picks the first free port
REM itself and --open opens the browser at exactly that port, so we
REM never have to guess which port it took - and never have to take
REM one from another project to get it.
REM
REM This runs the server in this window. Close it (or Ctrl+C) to stop.
call npm run dev -- --open

pause
exit /b
