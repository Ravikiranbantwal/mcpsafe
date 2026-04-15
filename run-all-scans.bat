@echo off
setlocal enabledelayedexpansion

REM ============================================================
REM  MCPSafe - Full regression scan (Windows batch version)
REM  Runs mcpsafe directly against the console (no pipes, no Tee)
REM  so stdio buffers never deadlock on chatty MCP servers.
REM ============================================================

cd /d "%~dp0"

set "OUTDIR=%~dp0mcpsafe-reports"
if not exist "%OUTDIR%" mkdir "%OUTDIR%"

set PYTHONUNBUFFERED=1
set PYTHONIOENCODING=utf-8

set "STARTALL=%TIME%"

REM ----------------------------------------------------------------
REM Free / no-auth targets
REM ----------------------------------------------------------------
call :RunScan  "mcp-calculator"      stdio  "python test_servers\mcp_calculator.py"
call :RunScan  "mcp-notes"            stdio  "python test_servers\mcp_notes.py"
call :RunScan  "mcp-text-processor"   stdio  "python test_servers\mcp_text_processor.py"
call :RunScan  "server-everything"    stdio  "npx -y @modelcontextprotocol/server-everything"
call :RunScan  "server-filesystem"    stdio  "npx -y @modelcontextprotocol/server-filesystem %TEMP%"
call :RunScan  "fetch"                stdio  "uvx mcp-server-fetch"
call :RunScan  "time"                 stdio  "uvx mcp-server-time"
call :RunScan  "git"                  stdio  "uvx mcp-server-git --repository %~dp0."
call :RunScan  "sqlite"               stdio  "uvx mcp-server-sqlite --db-path %TEMP%\mcpsafe-scan.db"

REM ----------------------------------------------------------------
REM Auth-required targets - prompt for each credential.
REM Press ENTER at the prompt to skip that server.
REM ----------------------------------------------------------------

call :PromptAuth "server-github" "GitHub Personal Access Token (ghp_... or github_pat_...)" "https://github.com/settings/tokens"
if defined AUTH_SECRET (
    call :RunScanEnv "server-github" stdio "npx -y @modelcontextprotocol/server-github" "GITHUB_PERSONAL_ACCESS_TOKEN" "!AUTH_SECRET!"
) else (
    echo   Skipped server-github ^(no credential^).
)

call :PromptAuth "cloudflare-docs" "Cloudflare API token for docs.mcp.cloudflare.com" "https://dash.cloudflare.com/profile/api-tokens"
if defined AUTH_SECRET (
    call :RunScanHeader "cloudflare-docs" http "https://docs.mcp.cloudflare.com/mcp" "Authorization" "Bearer !AUTH_SECRET!"
) else (
    echo   Skipped cloudflare-docs.
)

call :PromptAuth "cloudflare-observability" "Cloudflare API token for observability.mcp.cloudflare.com" "https://dash.cloudflare.com/profile/api-tokens"
if defined AUTH_SECRET (
    call :RunScanHeader "cloudflare-observability" http "https://observability.mcp.cloudflare.com/mcp" "Authorization" "Bearer !AUTH_SECRET!"
) else (
    echo   Skipped cloudflare-observability.
)

call :PromptAuth "stripe" "Stripe secret key (sk_test_... or sk_live_...)" "https://dashboard.stripe.com/test/apikeys"
if defined AUTH_SECRET (
    call :RunScanHeader "stripe" http "https://mcp.stripe.com/base" "Authorization" "Bearer !AUTH_SECRET!"
) else (
    echo   Skipped stripe.
)

echo.
echo ============================================================
echo                   MCPSAFE SCAN COMPLETE
echo ============================================================
echo Started:   %STARTALL%
echo Finished:  %TIME%
echo Reports:   %OUTDIR%
echo.
echo Open any *.html file in mcpsafe-reports\ to view a report.
echo.
endlocal
exit /b 0


REM ============================================================
REM  Subroutines
REM ============================================================

:RunScan
REM  %~1 = name   %~2 = transport   %~3 = target command
echo.
echo ----------------------------------------------------------------------
echo  SCAN: %~1  (%~2)
echo  Started at %TIME%
echo ----------------------------------------------------------------------
mcpsafe scan "%~3" --transport %~2 --output all --out-dir "%OUTDIR%" --verbose
echo   [exit=%ERRORLEVEL%] finished at %TIME%
exit /b 0


:RunScanEnv
REM  %~1 name   %~2 transport   %~3 target   %~4 env-var-name   %~5 secret
echo.
echo ----------------------------------------------------------------------
echo  SCAN: %~1  (%~2)  [env auth]
echo  Started at %TIME%
echo ----------------------------------------------------------------------
mcpsafe scan "%~3" --transport %~2 --output all --out-dir "%OUTDIR%" --env "%~4=%~5" --verbose
echo   [exit=%ERRORLEVEL%] finished at %TIME%
exit /b 0


:RunScanHeader
REM  %~1 name   %~2 transport   %~3 target   %~4 header-key   %~5 header-value
echo.
echo ----------------------------------------------------------------------
echo  SCAN: %~1  (%~2)  [header auth]
echo  Started at %TIME%
echo ----------------------------------------------------------------------
mcpsafe scan "%~3" --transport %~2 --output all --out-dir "%OUTDIR%" --header "%~4=%~5" --verbose
echo   [exit=%ERRORLEVEL%] finished at %TIME%
exit /b 0


:PromptAuth
REM  %~1 = server name   %~2 = prompt   %~3 = help-url
set "AUTH_SECRET="
echo.
echo --- CREDENTIAL NEEDED -------------------------------------------
echo   Server:  %~1
echo   Needs:   %~2
echo   Get it:  %~3
echo   (Press ENTER to skip this server.)
echo -----------------------------------------------------------------
set /p "AUTH_SECRET=Paste value: "
exit /b 0
