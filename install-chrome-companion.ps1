param (
    [Parameter(Mandatory=$true)]
    [string]$ExtensionId
)

$ErrorActionPreference = "Stop"

$HostName = "com.lumina.native_host"
$InstallDir = "$env:LOCALAPPDATA\Lumina\ChromeCompanion"
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

$ManifestPath = "$InstallDir\$HostName.json"
$ScriptPath = "$PSScriptRoot\extension-wrapper\lumina_host.py"

$ManifestJson = @{
    name = $HostName
    description = "Lumina Chrome Companion Native Messaging Host"
    path = "python.exe"
    args = @($ScriptPath)
    type = "stdio"
    allowed_origins = @("chrome-extension://$ExtensionId/")
} | ConvertTo-Json -Depth 4

Set-Content -Path $ManifestPath -Value $ManifestJson -Encoding UTF8

$RegistryKey = "HKCU:\Software\Google\Chrome\NativeMessagingHosts\$HostName"
if (-not (Test-Path $RegistryKey)) {
    New-Item -Path $RegistryKey -Force | Out-Null
}
Set-ItemProperty -Path $RegistryKey -Name "(default)" -Value $ManifestPath

Write-Host "[SUCCESS] Lumina Native Host registered successfully for Extension ID: $ExtensionId"
