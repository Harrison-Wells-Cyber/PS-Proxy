param(
    [string]$RepoRoot = (Resolve-Path "$PSScriptRoot/..").Path,
    [string]$OutFile = (Join-Path (Resolve-Path "$PSScriptRoot/..").Path "release/agent.ps1")
)
$ErrorActionPreference = "Stop"
$src = Join-Path $RepoRoot "agent/PSProxy.Agent/PSProxy.Agent.cs"
$dll = Join-Path $env:TEMP "PSProxy.Agent.dll"
$csc = Join-Path $env:WINDIR "Microsoft.NET/Framework64/v4.0.30319/csc.exe"
if (-not (Test-Path $csc)) { $csc = Join-Path $env:WINDIR "Microsoft.NET/Framework/v4.0.30319/csc.exe" }
if (-not (Test-Path $csc)) { throw "csc.exe for .NET Framework v4 was not found" }
& $csc /target:library /optimize+ /nologo /out:$dll $src
if ($LASTEXITCODE -ne 0) { throw "csc.exe failed" }
$raw = [IO.File]::ReadAllBytes($dll)
$ms = New-Object IO.MemoryStream
$gz = New-Object IO.Compression.GzipStream($ms, [IO.Compression.CompressionMode]::Compress)
$gz.Write($raw,0,$raw.Length); $gz.Dispose()
$b64 = [Convert]::ToBase64String($ms.ToArray())
$template = Get-Content (Join-Path $RepoRoot "agent/loader/agent.ps1.tmpl") -Raw
$template = $template.Replace('{{.AssemblyB64}}', $b64)
$template = $template.Replace('{{.Server}}', '__SERVER__')
$template = $template.Replace('{{.Port}}', '443')
$template = $template.Replace('{{.CertPin}}', '__CERT_PIN__')
$template = $template.Replace('{{.EnrollToken}}', '__ENROLL_TOKEN__')
[IO.File]::WriteAllText($OutFile, $template, [Text.Encoding]::UTF8)
Write-Host "Wrote $OutFile"
