# =========================================
# install.ps1 – OEM provisioning (Office + System prep)
# =========================================

$ErrorActionPreference = "Stop"

# -------------------------------------------------
# Global paths
# -------------------------------------------------

$OEMDIR        = "C:\OEM"
$ODTDIR        = Join-Path ${OEMDIR} "ODT"
$CACHE_ROOT    = Join-Path ${ODTDIR} "Office\Data"
$LOGDIR        = Join-Path ${OEMDIR} "logs"
$MARKER        = Join-Path ${LOGDIR} "oem_run.txt"

$ODT_EXE       = Join-Path ${ODTDIR} "ODT.EXE"
$SETUP_EXE     = Join-Path ${ODTDIR} "setup.exe"
$CONFIG_XML    = Join-Path ${ODTDIR} "config.xml"

$POSTLOGIN_BAT = Join-Path ${OEMDIR} "postlogin.bat"

# Force TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# -------------------------------------------------
# Create required directories
# -------------------------------------------------

foreach ($dir in @(${OEMDIR}, ${ODTDIR}, ${CACHE_ROOT}, ${LOGDIR})) {
    if (-not (Test-Path ${dir})) {
        New-Item -ItemType Directory -Force -Path ${dir} | Out-Null
    }
}

# Skip if already executed
if (Test-Path ${MARKER}) {
    Write-Output "OEM provisioning already completed. Exiting."
    exit 0
}

# -------------------------------------------------
# Download Office Deployment Tool (ODT)
# -------------------------------------------------

if (-not (Test-Path ${ODT_EXE})) {
    Write-Output "Downloading Office Deployment Tool..."
    Invoke-WebRequest `
        -Uri "https://download.microsoft.com/download/6c1eeb25-cf8b-41d9-8d0d-cc1dbc032140/officedeploymenttool_19426-20170.exe" `
        -OutFile ${ODT_EXE}
}

# -------------------------------------------------
# Extract ODT silently
# -------------------------------------------------

Write-Output "Extracting ODT..."
Start-Process `
    -FilePath ${ODT_EXE} `
    -ArgumentList @("/Extract:${ODTDIR}", "/Quiet") `
    -Wait

if (-not (Test-Path ${SETUP_EXE})) {
    Write-Error "ODT extraction failed - setup.exe missing"
    exit 1
}

# -------------------------------------------------
# Install Microsoft Office (ODT handles download + install)
# -------------------------------------------------

Write-Output "Installing Microsoft Office..."
Start-Process `
    -FilePath ${SETUP_EXE} `
    -WorkingDirectory ${ODTDIR} `
    -ArgumentList @("/configure", "${CONFIG_XML}") `
    -Wait

# -------------------------------------------------
# Load Default User Registry Hive
# -------------------------------------------------

Write-Output "Loading Default User registry hive..."

$DEFAULT_HIVE = "C:\Users\Default\NTUSER.DAT"
$DEFAULT_KEY  = "HKU\DefaultUser"

reg load ${DEFAULT_KEY} ${DEFAULT_HIVE} | Out-Null

# -------------------------------------------------
# Apply Default User Tweaks
# -------------------------------------------------

Write-Output "Applying Default User registry tweaks..."

# Show file extensions
reg add "${DEFAULT_KEY}\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" `
    /v HideFileExt /t REG_DWORD /d 0 /f | Out-Null

# Disable first-run privacy experience
reg add "${DEFAULT_KEY}\Software\Microsoft\Windows\CurrentVersion\Privacy" `
    /v TailoredExperiencesWithDiagnosticDataEnabled /t REG_DWORD /d 0 /f | Out-Null

# Disable Edge first-run
reg add "${DEFAULT_KEY}\Software\Microsoft\Edge" `
    /v HideFirstRunExperience /t REG_DWORD /d 1 /f | Out-Null

# -------------------------------------------------
# Unload Default User Registry Hive
# -------------------------------------------------

Write-Output "Unloading Default User registry hive..."
reg unload ${DEFAULT_KEY} | Out-Null

# -------------------------------------------------
# Apply Office Policies (machine-wide)
# -------------------------------------------------

Write-Output "Applying Office policies..."

$OFFICE_POL = "HKLM\Software\Policies\Microsoft\Office\16.0\Common"

# Disable Office first-run
reg add "${OFFICE_POL}\General" `
    /v DisableFirstRunExperience /t REG_DWORD /d 1 /f | Out-Null

# Disable telemetry
reg add "${OFFICE_POL}" `
    /v SendTelemetry /t REG_DWORD /d 0 /f | Out-Null

# Disable connected experiences
reg add "${OFFICE_POL}\Privacy" `
    /v ConnectedExperiencesEnabled /t REG_DWORD /d 0 /f | Out-Null

# -------------------------------------------------
# Create Scheduled Task for postlogin.bat
# -------------------------------------------------

<#
if (Test-Path ${POSTLOGIN_BAT}) {

    Write-Output "Creating Scheduled Task for post-login actions..."

    schtasks /create /f `
        /sc ONLOGON `
        /ru SYSTEM `
        /rl HIGHEST `
        /tn "OEM-PostLogin" `
        /tr "cmd.exe /c ${POSTLOGIN_BAT}" | Out-Null
}
#>

# -------------------------------------------------
# Cleanup ODT and cache
# -------------------------------------------------

Write-Output "Cleaning up ODT and Office cache..."

# Remove Office payload cache
if (Test-Path ${CACHE_ROOT}) {
    Remove-Item -Recurse -Force ${CACHE_ROOT} -ErrorAction SilentlyContinue
}

# Remove extracted ODT binaries (keep config.xml)
Get-ChildItem ${ODTDIR} -Exclude "config.xml" -Recurse -Force `
    | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue


# -------------------------------------------------
# Apply RDP Apps Policies (machine-wide)
# -------------------------------------------------

Write-Output "Applying RDP Apps policies..."

# Disable RemoteApp allowlist so all applications can be used in Remote Desktop sessions
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\TSAppAllowList" `
    /v fDisabledAllowList /t REG_DWORD /d 1 /f | Out-Null

# Allow unlisted programs to be run in Remote Desktop sessions
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
    /v fAllowUnlistedRemotePrograms /t REG_DWORD /d 1 /f | Out-Null

# Disable automatic administrator logon at startup
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" `
    /v AutoAdminLogon /t REG_SZ /d "0" /f | Out-Null

# Always use the server's keyboard layout, TODO Investigate
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Keyboard Layout" `
    /v IgnoreRemoteKeyboardLayout /t REG_DWORD /d 1 /f | Out-Null

# Disable new network location wizard
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Network\NewNetworkWindowOff" /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Network\NetworkLocationWizard" `
    /v HideWizard /t REG_DWORD /d 1 /f | Out-Null


# -------------------------------------------------
# DISM component cleanup
# -------------------------------------------------

Write-Output "Running DISM cleanup..."

Start-Process `
    -FilePath "dism.exe" `
    -ArgumentList @(
        "/Online",
        "/Cleanup-Image",
        "/StartComponentCleanup",
        "/ResetBase"
    ) `
    -Wait

# -------------------------------------------------
# Final marker
# -------------------------------------------------

New-Item -ItemType File -Force -Path ${MARKER} | Out-Null
Write-Output "OEM provisioning completed successfully."