$ErrorActionPreference = 'Stop'

$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe'
$output = Join-Path $PSScriptRoot 'Install-NucCertificates.exe'
$source = Join-Path $PSScriptRoot 'Install-NucCertificates.cs'
$icon = Join-Path $PSScriptRoot 'Install-NucCertificates.ico'
$certificateNames = @(
    'Russian_Trusted_Root_CA.cer'
    'Russian_Trusted_Sub_CA.cer'
    'Russian_Trusted_Sub_CA_2024.cer'
)
$resources = foreach ($name in $certificateNames) {
    $path = Join-Path $PSScriptRoot "certificates\$name"
    "/resource:$path,$name"
}

& $compiler /nologo /target:exe /platform:anycpu /optimize+ /warnaserror+ /codepage:65001 "/out:$output" "/win32icon:$icon" @resources $source
if ($LASTEXITCODE -ne 0) {
    throw "Build failed (exit code $LASTEXITCODE)."
}

Get-Item -LiteralPath $output
