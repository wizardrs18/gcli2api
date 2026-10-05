$ErrorActionPreference = "Stop"

$projectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$pythonPath = Join-Path $projectDir ".venv\Scripts\python.exe"
$panelUrl = "http://127.0.0.1:7861/"
$stdoutLog = Join-Path $env:TEMP "gcli2api-panel.stdout.log"
$stderrLog = Join-Path $env:TEMP "gcli2api-panel.stderr.log"

function Test-PanelPort {
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $attempt = $client.BeginConnect("127.0.0.1", 7861, $null, $null)
        if (-not $attempt.AsyncWaitHandle.WaitOne(300)) {
            return $false
        }
        $client.EndConnect($attempt)
        return $true
    }
    catch {
        return $false
    }
    finally {
        $client.Close()
    }
}

if (-not (Test-Path -LiteralPath $pythonPath)) {
    Add-Type -AssemblyName PresentationFramework
    [System.Windows.MessageBox]::Show(
        "找不到虚拟环境：$pythonPath",
        "GCLI2API 管理面板",
        "OK",
        "Error"
    ) | Out-Null
    exit 1
}

if (-not (Test-PanelPort)) {
    $serverProcess = Start-Process `
        -FilePath $pythonPath `
        -ArgumentList "web.py" `
        -WorkingDirectory $projectDir `
        -WindowStyle Hidden `
        -RedirectStandardOutput $stdoutLog `
        -RedirectStandardError $stderrLog `
        -PassThru

    $ready = $false
    for ($attemptNumber = 0; $attemptNumber -lt 40; $attemptNumber++) {
        Start-Sleep -Milliseconds 500
        if (Test-PanelPort) {
            $ready = $true
            break
        }
        if ($serverProcess.HasExited) {
            break
        }
    }

    if (-not $ready) {
        Add-Type -AssemblyName PresentationFramework
        [System.Windows.MessageBox]::Show(
            "服务启动失败。错误日志：$stderrLog",
            "GCLI2API 管理面板",
            "OK",
            "Error"
        ) | Out-Null
        exit 1
    }
}

Start-Process -FilePath (Join-Path $env:WINDIR "explorer.exe") -ArgumentList $panelUrl
