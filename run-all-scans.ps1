# -----------------------------------------------------------------------------
# MCPSafe - Full regression scan across every previously-tested server
#
# Usage:
#     cd C:\Users\bantw\Documents\Claude\Projects\MCPSafe
#     .\run-all-scans.ps1
#
# - Scans all free / no-auth servers automatically.
# - When an auth-required server is reached the script prompts for the
#   token. Press ENTER on the prompt to skip that server.
# - Writes JSON + HTML + SARIF reports into .\mcpsafe-reports\
# - Logs a one-line summary for each target at the end.
# -----------------------------------------------------------------------------

$ErrorActionPreference = "Continue"
$ProjectRoot = $PSScriptRoot
Set-Location $ProjectRoot

$OutDir = Join-Path $ProjectRoot "mcpsafe-reports"
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }

# ---------------------------------------------------------------------------
# Output handling - flush Python stdout immediately and use UTF-8.
# We intentionally do NOT set RICH_FORCE_TERMINAL - through a PowerShell pipe
# that flag makes rich re-emit every progress frame as new output, flooding
# the console with duplicates.  Instead we use --verbose so each finding
# prints as a discrete panel that streams cleanly.
# ---------------------------------------------------------------------------
$env:PYTHONUNBUFFERED = "1"
$env:PYTHONIOENCODING = "utf-8"

function Read-Secret {
    param(
        [string]$Prompt,
        [string]$HelpUrl = ""
    )
    Write-Host ""
    Write-Host "--- CREDENTIAL NEEDED ---------------------------------------" -ForegroundColor Yellow
    Write-Host " $Prompt" -ForegroundColor Yellow
    if ($HelpUrl) {
        Write-Host " Get one here: $HelpUrl" -ForegroundColor DarkGray
    }
    Write-Host " (Press ENTER to skip this server and move on.)" -ForegroundColor DarkGray
    Write-Host "-------------------------------------------------------------" -ForegroundColor Yellow
    $secure = Read-Host "Paste value" -AsSecureString
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    $plain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    return $plain
}

# --- Free / no-auth targets --------------------------------------------------
$FreeTargets = @(
    @{ Name = "mcp-calculator";      Transport = "stdio"; Target = "python test_servers\mcp_calculator.py" },
    @{ Name = "mcp-notes";            Transport = "stdio"; Target = "python test_servers\mcp_notes.py" },
    @{ Name = "mcp-text-processor";   Transport = "stdio"; Target = "python test_servers\mcp_text_processor.py" },
    @{ Name = "server-everything";    Transport = "stdio"; Target = "npx -y @modelcontextprotocol/server-everything" },
    @{ Name = "server-filesystem";    Transport = "stdio"; Target = "npx -y @modelcontextprotocol/server-filesystem $env:TEMP" },
    @{ Name = "fetch";                Transport = "stdio"; Target = "uvx mcp-server-fetch" },
    @{ Name = "time";                 Transport = "stdio"; Target = "uvx mcp-server-time" },
    @{ Name = "git";                  Transport = "stdio"; Target = "uvx mcp-server-git --repository $ProjectRoot" },
    @{ Name = "sqlite";               Transport = "stdio"; Target = "uvx mcp-server-sqlite --db-path $env:TEMP\mcpsafe-scan.db" }
)

# --- Auth-required targets - prompt for key at scan time --------------------
$AuthTargets = @(
    @{
        Name      = "server-github"
        Transport = "stdio"
        Target    = "npx -y @modelcontextprotocol/server-github"
        InjectAs  = "env"
        EnvName   = "GITHUB_PERSONAL_ACCESS_TOKEN"
        Prompt    = "GitHub Personal Access Token (ghp_... or github_pat_...)"
        HelpUrl   = "https://github.com/settings/tokens"
    },
    @{
        Name         = "cloudflare-docs"
        Transport    = "http"
        Target       = "https://docs.mcp.cloudflare.com/mcp"
        InjectAs     = "header"
        HeaderKey    = "Authorization"
        HeaderPrefix = "Bearer "
        Prompt       = "Cloudflare API token for docs.mcp.cloudflare.com"
        HelpUrl      = "https://dash.cloudflare.com/profile/api-tokens"
    },
    @{
        Name         = "cloudflare-observability"
        Transport    = "http"
        Target       = "https://observability.mcp.cloudflare.com/mcp"
        InjectAs     = "header"
        HeaderKey    = "Authorization"
        HeaderPrefix = "Bearer "
        Prompt       = "Cloudflare API token for observability.mcp.cloudflare.com"
        HelpUrl      = "https://dash.cloudflare.com/profile/api-tokens"
    },
    @{
        Name         = "stripe"
        Transport    = "http"
        Target       = "https://mcp.stripe.com/base"
        InjectAs     = "header"
        HeaderKey    = "Authorization"
        HeaderPrefix = "Bearer "
        Prompt       = "Stripe secret key (sk_test_... or sk_live_...)"
        HelpUrl      = "https://dashboard.stripe.com/test/apikeys"
    }
)

# --- Scan loop --------------------------------------------------------------
$Results = @()
$StartedAll = Get-Date

function Invoke-Scan {
    param([hashtable]$t, [string[]]$extraArgs = @())

    $banner = "-" * 70
    Write-Host ""
    Write-Host $banner -ForegroundColor Cyan
    Write-Host " SCAN: $($t.Name)  ($($t.Transport))" -ForegroundColor Cyan
    Write-Host $banner -ForegroundColor Cyan

    $cmdArgs = @(
        "scan",
        $t.Target,
        "--transport", $t.Transport,
        "--output", "all",
        "--out-dir", $OutDir,
        "--verbose"
    ) + $extraArgs

    Write-Host ("  Started at " + (Get-Date -Format "HH:mm:ss") + " - typical scan time 1-3 min per server, then summary prints.") -ForegroundColor DarkGray
    Write-Host ""

    $start = Get-Date
    & mcpsafe @cmdArgs
    $exitCode = $LASTEXITCODE
    $elapsed = (Get-Date) - $start

    return [PSCustomObject]@{
        Server    = $t.Name
        Transport = $t.Transport
        ExitCode  = $exitCode
        Duration  = "{0:mm\:ss}" -f $elapsed
    }
}

# Free targets - no prompts.
foreach ($t in $FreeTargets) {
    $Results += Invoke-Scan -t $t
}

# Auth-required targets - prompt before each.
foreach ($t in $AuthTargets) {
    $secret = Read-Secret -Prompt $t.Prompt -HelpUrl $t.HelpUrl
    if ([string]::IsNullOrWhiteSpace($secret)) {
        Write-Host "  -> Skipped $($t.Name) (no credential supplied)." -ForegroundColor DarkGray
        $Results += [PSCustomObject]@{
            Server    = $t.Name
            Transport = $t.Transport
            ExitCode  = "SKIP"
            Duration  = "-"
        }
        continue
    }

    $extra = @()
    switch ($t.InjectAs) {
        "env" {
            $extra += @("--env", "$($t.EnvName)=$secret")
        }
        "header" {
            $prefix = $t.HeaderPrefix
            if (-not $prefix) { $prefix = "" }
            $extra += @("--header", "$($t.HeaderKey)=$prefix$secret")
        }
        default {
            Write-Host "  -> Unknown InjectAs mode for $($t.Name) - skipping." -ForegroundColor Red
            continue
        }
    }

    $Results += Invoke-Scan -t $t -extraArgs $extra
}

$totalElapsed = (Get-Date) - $StartedAll

# --- Summary ----------------------------------------------------------------
Write-Host ""
Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "                   MCPSAFE SCAN SUMMARY                     " -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
$Results | Format-Table -AutoSize

$reportCount = (Get-ChildItem $OutDir -Filter "*.json" | Measure-Object).Count
Write-Host ("Total wall-clock time: {0:hh\:mm\:ss}" -f $totalElapsed) -ForegroundColor Yellow
Write-Host "Reports directory:     $OutDir" -ForegroundColor Yellow
Write-Host "JSON reports on disk:  $reportCount" -ForegroundColor Yellow
Write-Host ""
Write-Host "Open any *.html file in mcpsafe-reports\ to view a report." -ForegroundColor Yellow
Write-Host ""
