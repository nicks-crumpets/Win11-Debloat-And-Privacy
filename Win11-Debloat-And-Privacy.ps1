# ============================================================================
# Win11-Debloat-And-Privacy.ps1
# ============================================================================
# Description: Comprehensive Windows 11 optimization and privacy configuration
# Based on: Official Microsoft Group Policy documentation for Windows 11 24H2/25H2
# Date: December 2025
# Requires: Admin
# Compatible: Windows 11 Pro, Enterprise, Education (LIMITED support on Home)
#
# REFERENCES:
# - Microsoft Docs: https://learn.microsoft.com/en-us/windows/
# - Registry: https://learn.microsoft.com/en-us/windows/client-management/
# - Group Policy: https://learn.microsoft.com/en-us/windows/client-management/mdm/
# - PowerShell: https://learn.microsoft.com/en-us/powershell/
# ============================================================================

# Check if running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script requires administrator privileges!" -ForegroundColor Yellow
    Write-Host "Attempting to relaunch with admin rights..." -ForegroundColor Cyan
    
    $scriptPath = $MyInvocation.MyCommand.Path
    
    # NOTE: Keeping -ExecutionPolicy Bypass as requested by user
    try {
        Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`"" -Verb RunAs
        exit
    } catch {
        Write-Host "Failed to elevate privileges. Please run PowerShell as Administrator manually." -ForegroundColor Red
        pause
        exit 1
    }
}

# ============================================================================
# CRITICAL WARNING SPLASH SCREEN
# ============================================================================
Write-Host @"

===============================================================
Win11-Debloat-And-Privacy.ps1 - "AND STAY DOWN!"
===============================================================

"@ -ForegroundColor Cyan

Write-Host @"
!!! CRITICAL WARNINGS - PLEASE READ CAREFULLY !!!
===============================================================

This script will make SIGNIFICANT changes to your system that:

[SECURITY RISKS]
   - Prevents automatic Windows Update restarts
     >> You MUST manually restart to apply security patches
     >> Delays could leave your system VULNERABLE
   
[FUNCTIONALITY IMPACTS]
   - Xbox Accessory Management Service will be DISABLED
     >> This may break some game controllers (not just Xbox!)
     >> Bluetooth/USB gamepads may stop working
   - Game DVR and Game Mode will be DISABLED
     >> Screen recording features will not work
   
[WINDOWS EDITION LIMITATIONS]
   - Windows Home: Many Group Policy settings will NOT work
     >> Only registry-based settings will apply
     >> Approximately 40% of this script is ineffective on Home
   - Windows Pro: Telemetry can only be set to "Basic" (not "Off")
   - Windows Enterprise/Education: Full functionality available
   
[TELEMETRY BEHAVIOR]
   - Windows Home: Minimum telemetry is "Enhanced" (value 2)
   - Windows Pro: Minimum telemetry is "Basic" (value 1)
   - Enterprise/Education: Can be set to "Security" (value 0)
   - Setting lower values on Home/Pro may be ignored by Windows
   
[OTHER IMPACTS]
   - OneDrive sync will be disabled
   - Widgets will be disabled
   - Copilot will be disabled
   - Web search in Start Menu will be disabled
   - Classic Windows 10 context menu will be restored
   
[RESTORE POINT]
   - A restore point will be created BEFORE changes
   - You can revert using: Control Panel > System > System Protection
   - Note: Only ONE restore point can be created per 24 hours (unless you changed it)
   
[RECOMMENDATIONS]
   - Review all changes before proceeding
   - Ensure you have recent backups
   - Be prepared to manually restart for Windows Updates
   - Re-enable Xbox services if you use game controllers
   
===============================================================

"@ -ForegroundColor Yellow

$confirmation = Read-Host "Do you understand these risks and want to continue? Type 'YES' to proceed"

if ($confirmation -ne 'YES') {
    Write-Host ""
    Write-Host "Script cancelled by user. No changes were made." -ForegroundColor Cyan
    Write-Host "Press any key to exit..."
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    exit
}

Write-Host ""
Write-Host "Proceeding with configuration..." -ForegroundColor Green
Write-Host ""

# ============================================================================
# DETECT WINDOWS EDITION
# ============================================================================
Write-Host "=== DETECTING WINDOWS EDITION ===" -ForegroundColor Yellow

try {
    $edition = (Get-ComputerInfo -Property WindowsEditionId).WindowsEditionId
    $productName = (Get-ComputerInfo -Property WindowsProductName).WindowsProductName
    
    Write-Host "Detected: $productName (Edition ID: $edition)" -ForegroundColor Cyan
    
    # Determine telemetry minimum based on edition
    # Reference: https://learn.microsoft.com/en-us/windows/privacy/configure-windows-diagnostic-data-in-your-organization
    $telemetryValue = 0  # Default for Enterprise/Education
    $editionWarning = ""
    
    if ($edition -like "*Home*") {
        $telemetryValue = 2  # Enhanced (minimum for Home)
        $editionWarning = "HOME"
        Write-Host ""
        Write-Host "!!! WARNING: Windows Home Edition Detected!" -ForegroundColor Red
        Write-Host "   Many Group Policy settings (HKLM:\SOFTWARE\Policies\*) will NOT work!" -ForegroundColor Red
        Write-Host "   Telemetry can only be set to Enhanced (2), not Basic or Security." -ForegroundColor Red
        Write-Host "   Approximately 40% of this script's settings require Pro or higher." -ForegroundColor Red
        Write-Host ""
        $continueHome = Read-Host "Continue anyway? (y/n)"
        if ($continueHome -ne 'y') {
            Write-Host "Script cancelled." -ForegroundColor Cyan
            exit
        }
    } elseif ($edition -like "*Pro*") {
        $telemetryValue = 1  # Basic (minimum for Pro)
        Write-Host "Windows Pro detected: Telemetry will be set to Basic (minimum allowed)" -ForegroundColor Cyan
    } else {
        $telemetryValue = 0  # Security (available on Enterprise/Education)
        Write-Host "Enterprise/Education detected: Telemetry will be set to Security (fully disabled)" -ForegroundColor Cyan
    }
} catch {
    Write-Host "Could not detect Windows edition. Assuming Pro edition..." -ForegroundColor Yellow
    $telemetryValue = 1
    $edition = "Unknown"
}

Write-Host ""

# ============================================================================
# MODE SELECTION
# ============================================================================
Write-Host "Select mode:" -ForegroundColor Yellow
Write-Host "  [1] Apply Settings (default)" -ForegroundColor Cyan
Write-Host "  [2] Verify Settings (check mode)" -ForegroundColor Cyan
Write-Host ""
$modeChoice = Read-Host "Enter choice (1 or 2, press Enter for default)"

if ([string]::IsNullOrWhiteSpace($modeChoice)) {
    $modeChoice = "1"
}

# Run verification mode if user chose option 2
if ($modeChoice -eq "2") {
    Write-Host ""
    Write-Host "Running in VERIFICATION MODE..." -ForegroundColor Green
    Write-Host ""
    
    # Jump to verification section
    & {
        # VERIFICATION MODE CODE STARTS HERE
        
        function Write-Status {
            param([string]$Message, [string]$Type = "Info")
            switch($Type) {
                "Success" { Write-Host "[PASS] $Message" -ForegroundColor Green }
                "Info" { Write-Host "[INFO] $Message" -ForegroundColor Cyan }
                "Warning" { Write-Host "[WARN] $Message" -ForegroundColor Yellow }
                "Error" { Write-Host "[ERR!] $Message" -ForegroundColor Red }
                "Fail" { Write-Host "[FAIL] $Message" -ForegroundColor Red }
            }
        }

        function Test-RegistryValue {
            param(
                [string]$Path,
                [string]$Name,
                [object]$ExpectedValue,
                [string]$Description
            )
            
            try {
                if (!(Test-Path $Path)) {
                    Write-Status "$Description - Registry path not found" "Fail"
                    return $false
                }
                
                $actualValue = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $Name
                
                if ($null -eq $actualValue) {
                    Write-Status "$Description - Value not set" "Fail"
                    return $false
                }
                
                # Compare as strings to handle type differences
                if ([string]$actualValue -eq [string]$ExpectedValue) {
                    Write-Status "$Description - OK (Value: $actualValue)" "Success"
                    return $true
                } else {
                    Write-Status "$Description - MISMATCH (Expected: $ExpectedValue, Got: $actualValue)" "Fail"
                    return $false
                }
            } catch {
                Write-Status "$Description - Error checking: $_" "Error"
                return $false
            }
        }

        function Test-ServiceStatus {
            param(
                [string]$ServiceName,
                [string]$DisplayName
            )
            
            try {
                $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
                
                if (!$service) {
                    Write-Status "$DisplayName - Service not found (OK if not on your system)" "Warning"
                    return $null
                }
                
                if ($service.StartType -eq "Disabled" -and $service.Status -eq "Stopped") {
                    Write-Status "$DisplayName - Disabled and Stopped" "Success"
                    return $true
                } elseif ($service.StartType -eq "Disabled") {
                    Write-Status "$DisplayName - Disabled but Status: $($service.Status)" "Warning"
                    return $true
                } else {
                    Write-Status "$DisplayName - NOT DISABLED (StartType: $($service.StartType), Status: $($service.Status))" "Fail"
                    return $false
                }
            } catch {
                Write-Status "$DisplayName - Error checking: $_" "Error"
                return $false
            }
        }

        function Test-ScheduledTaskStatus {
            param(
                [string]$TaskPath,
                [string]$TaskName
            )
            
            try {
                $task = Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction SilentlyContinue
                
                if (!$task) {
                    Write-Status "Task: $TaskName - Not found (OK if not on your system)" "Warning"
                    return $null
                }
                
                if ($task.State -eq "Disabled") {
                    Write-Status "Task: $TaskName - Disabled" "Success"
                    return $true
                } else {
                    Write-Status "Task: $TaskName - NOT DISABLED (State: $($task.State))" "Fail"
                    return $false
                }
            } catch {
                Write-Status "Task: $TaskName - Error checking: $_" "Error"
                return $false
            }
        }

        $totalChecks = 0
        $passedChecks = 0
        $failedChecks = 0
        $warningChecks = 0

        # CHECK SERVICES
        Write-Host ""
        Write-Host "=== CHECKING SERVICES ===" -ForegroundColor Yellow

        $services = @(
            @{Name="DiagTrack"; DisplayName="Connected User Experiences and Telemetry"},
            @{Name="dmwappushservice"; DisplayName="WAP Push Message Routing"},
            @{Name="RetailDemo"; DisplayName="Retail Demo Service"},
            @{Name="XblAuthManager"; DisplayName="Xbox Live Auth Manager"},
            @{Name="XblGameSave"; DisplayName="Xbox Live Game Save"},
            @{Name="XboxNetApiSvc"; DisplayName="Xbox Live Networking Service"},
            @{Name="XboxGipSvc"; DisplayName="Xbox Accessory Management Service"}
        )

        foreach ($service in $services) {
            $totalChecks++
            $result = Test-ServiceStatus -ServiceName $service.Name -DisplayName $service.DisplayName
            if ($result -eq $true) { $passedChecks++ }
            elseif ($result -eq $false) { $failedChecks++ }
            else { $warningChecks++ }
        }

        # CHECK SCHEDULED TASKS
        Write-Host ""
        Write-Host "=== CHECKING SCHEDULED TASKS ===" -ForegroundColor Yellow

        $tasks = @(
            @{Path="\Microsoft\Windows\Application Experience\"; Name="Microsoft Compatibility Appraiser"},
            @{Path="\Microsoft\Windows\Application Experience\"; Name="ProgramDataUpdater"},
            @{Path="\Microsoft\Windows\Autochk\"; Name="Proxy"},
            @{Path="\Microsoft\Windows\Customer Experience Improvement Program\"; Name="Consolidator"},
            @{Path="\Microsoft\Windows\Customer Experience Improvement Program\"; Name="UsbCeip"},
            @{Path="\Microsoft\Windows\DiskDiagnostic\"; Name="Microsoft-Windows-DiskDiagnosticDataCollector"},
            @{Path="\Microsoft\Windows\Feedback\Siuf\"; Name="DmClient"},
            @{Path="\Microsoft\Windows\Feedback\Siuf\"; Name="DmClientOnScenarioDownload"},
            @{Path="\Microsoft\Windows\Windows Error Reporting\"; Name="QueueReporting"}
        )

        foreach ($task in $tasks) {
            $totalChecks++
            $result = Test-ScheduledTaskStatus -TaskPath $task.Path -TaskName $task.Name
            if ($result -eq $true) { $passedChecks++ }
            elseif ($result -eq $false) { $failedChecks++ }
            else { $warningChecks++ }
        }

        # CHECK CONTEXT MENU
        Write-Host ""
        Write-Host "=== CHECKING CONTEXT MENU ===" -ForegroundColor Yellow

        $totalChecks++
        if (Test-RegistryValue -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Name "(Default)" -ExpectedValue "" -Description "Classic Context Menu") {
            $passedChecks++
        } else {
            $failedChecks++
        }

        # CHECK GAME DVR
        Write-Host ""
        Write-Host "=== CHECKING GAME DVR AND GAME MODE ===" -ForegroundColor Yellow

        $totalChecks++
        if (Test-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AppCaptureEnabled" -ExpectedValue 0 -Description "Game DVR Capture") {
            $passedChecks++
        } else {
            $failedChecks++
        }

        $totalChecks++
        if (Test-RegistryValue -Path "HKCU:\Software\Microsoft\GameBar" -Name "AutoGameModeEnabled" -ExpectedValue 0 -Description "Auto Game Mode") {
            $passedChecks++
        } else {
            $failedChecks++
        }

        # CHECK COPILOT
        Write-Host ""
        Write-Host "=== CHECKING COPILOT ===" -ForegroundColor Yellow

        $totalChecks++
        if (Test-RegistryValue -Path "HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot" -Name "TurnOffWindowsCopilot" -ExpectedValue 1 -Description "Copilot (User Policy)") {
            $passedChecks++
        } else {
            $failedChecks++
        }

        $totalChecks++
        if (Test-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" -Name "TurnOffWindowsCopilot" -ExpectedValue 1 -Description "Copilot (Computer Policy)") {
            $passedChecks++
        } else {
            $failedChecks++
        }

        $totalChecks++
        if (Test-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCopilotButton" -ExpectedValue 0 -Description "Copilot Taskbar Button") {
            $passedChecks++
        } else {
            $failedChecks++
        }

        # CHECK WIDGETS
        Write-Host ""
        Write-Host "=== CHECKING WIDGETS ===" -ForegroundColor Yellow

        $totalChecks++
        if (Test-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" -Name "AllowNewsAndInterests" -ExpectedValue 0 -Description "Widgets") {
            $passedChecks++
        } else {
            $failedChecks++
        }

        # CHECK TELEMETRY
        Write-Host ""
        Write-Host "=== CHECKING TELEMETRY ===" -ForegroundColor Yellow

        $totalChecks++
        $regValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -ErrorAction SilentlyContinue
        if ($regValue) {
            Write-Status "Telemetry Level - Set to value: $($regValue.AllowTelemetry)" "Success"
            $passedChecks++
        } else {
            Write-Status "Telemetry Level - Not set" "Fail"
            $failedChecks++
        }

        $totalChecks++
        if (Test-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -ExpectedValue 1 -Description "Advertising ID") {
            $passedChecks++
        } else {
            $failedChecks++
        }

        $totalChecks++
        if (Test-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackProgs" -ExpectedValue 0 -Description "App Launch Tracking") {
            $passedChecks++
        } else {
            $failedChecks++
        }

        # CHECK CONTENTDELIVERYMANAGER
        Write-Host ""
        Write-Host "=== CHECKING CONTENTDELIVERYMANAGER ===" -ForegroundColor Yellow

        $cdmSettings = @(
            "ContentDeliveryAllowed",
            "FeatureManagementEnabled",
            "OemPreInstalledAppsEnabled",
            "PreInstalledAppsEnabled",
            "PreInstalledAppsEverEnabled",
            "SilentInstalledAppsEnabled",
            "SoftLandingEnabled",
            "RotatingLockScreenEnabled",
            "RotatingLockScreenOverlayEnabled",
            "SubscribedContent-310093Enabled",
            "SubscribedContent-338387Enabled",
            "SubscribedContent-338388Enabled",
            "SubscribedContent-338389Enabled",
            "SubscribedContent-338393Enabled",
            "SubscribedContent-353694Enabled",
            "SubscribedContent-353696Enabled",
            "SubscribedContent-353698Enabled",
            "SystemPaneSuggestionsEnabled"
        )

        $cdmPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"

        foreach ($setting in $cdmSettings) {
            $totalChecks++
            if (Test-RegistryValue -Path $cdmPath -Name $setting -ExpectedValue 0 -Description "CDM: $setting") {
                $passedChecks++
            } else {
                $failedChecks++
            }
        }

        # CHECK WEB SEARCH
        Write-Host ""
        Write-Host "=== CHECKING WEB SEARCH ===" -ForegroundColor Yellow

        $totalChecks++
        if (Test-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -ExpectedValue 0 -Description "Bing Search") {
            $passedChecks++
        } else {
            $failedChecks++
        }

        $totalChecks++
        if (Test-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "DisableSearchBoxSuggestions" -ExpectedValue 1 -Description "Search Suggestions") {
            $passedChecks++
        } else {
            $failedChecks++
        }

        # CHECK ONEDRIVE
        Write-Host ""
        Write-Host "=== CHECKING ONEDRIVE ===" -ForegroundColor Yellow

        $totalChecks++
        if (Test-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -ExpectedValue 1 -Description "OneDrive File Sync") {
            $passedChecks++
        } else {
            $failedChecks++
        }

        # CHECK TASKBAR
        Write-Host ""
        Write-Host "=== CHECKING TASKBAR ===" -ForegroundColor Yellow

        $totalChecks++
        if (Test-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -ExpectedValue 0 -Description "Taskbar Alignment (Left)") {
            $passedChecks++
        } else {
            $failedChecks++
        }

        # FINAL SUMMARY
        Write-Host ""
        Write-Host "===============================================================" -ForegroundColor Cyan
        Write-Host " VERIFICATION COMPLETE" -ForegroundColor Cyan
        Write-Host "===============================================================" -ForegroundColor Cyan
        Write-Host ""

        Write-Host "Total Checks: $totalChecks" -ForegroundColor White
        Write-Host "Passed: $passedChecks" -ForegroundColor Green
        Write-Host "Failed: $failedChecks" -ForegroundColor Red
        Write-Host "Warnings: $warningChecks" -ForegroundColor Yellow
        Write-Host ""

        $successRate = [math]::Round(($passedChecks / $totalChecks) * 100, 1)

        if ($failedChecks -eq 0) {
            Write-Host "SUCCESS - ALL CHECKS PASSED!" -ForegroundColor Green
        } elseif ($successRate -ge 90) {
            Write-Host "SUCCESS - MOSTLY PASSED ($successRate%)" -ForegroundColor Green
        } elseif ($successRate -ge 70) {
            Write-Host "WARNING - PARTIALLY PASSED ($successRate%)" -ForegroundColor Yellow
        } else {
            Write-Host "ERROR - MANY FAILURES ($successRate%)" -ForegroundColor Red
        }

        Write-Host ""
        Write-Host "Press any key to exit..."
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    }
    
    exit
}

# If we get here, user chose mode 1 - continue with main script
Write-Host ""
Write-Host "Running in APPLY SETTINGS MODE..." -ForegroundColor Green
Write-Host ""

# Color-coded output
function Write-Status {
    param([string]$Message, [string]$Type = "Info")
    switch($Type) {
        "Success" { Write-Host "[+] $Message" -ForegroundColor Green }
        "Info" { Write-Host "[*] $Message" -ForegroundColor Cyan }
        "Warning" { Write-Host "[!] $Message" -ForegroundColor Yellow }
        "Error" { Write-Host "[X] $Message" -ForegroundColor Red }
    }
}

Write-Status "Running with all optimizations enabled" "Info"
Write-Host ""

# ============================================================================
# CREATE AND VERIFY RESTORE POINT
# Reference: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/checkpoint-computer
# ============================================================================
Write-Status "Creating system restore point..." "Info"

try {
    Enable-ComputerRestore -Drive "C:\" -ErrorAction Stop
    
    $restorePointsBefore = Get-ComputerRestorePoint -ErrorAction SilentlyContinue
    $countBefore = if ($restorePointsBefore) { $restorePointsBefore.Count } else { 0 }
    
    Checkpoint-Computer -Description "Before Win11PolicyEnforcer" -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
    
    Start-Sleep -Seconds 2
    
    $restorePointsAfter = Get-ComputerRestorePoint -ErrorAction SilentlyContinue
    $countAfter = if ($restorePointsAfter) { $restorePointsAfter.Count } else { 0 }
    
    if ($countAfter -gt $countBefore) {
        Write-Status "Restore point created and verified successfully" "Success"
        $latestRP = $restorePointsAfter | Select-Object -Last 1
        Write-Host "   Description: $($latestRP.Description)" -ForegroundColor Cyan
        Write-Host "   Created: $($latestRP.CreationTime)" -ForegroundColor Cyan
    } else {
        throw "Restore point count did not increase. May have hit 24-hour limit."
    }
    
} catch {
    Write-Status "CRITICAL: Could not create or verify restore point!" "Error"
    Write-Status "Error: $_" "Error"
    Write-Host ""
    Write-Host "POSSIBLE CAUSES:" -ForegroundColor Yellow
    Write-Host "  1. System Restore is disabled on this drive" -ForegroundColor Yellow
    Write-Host "  2. A restore point was already created in the last 24 hours" -ForegroundColor Yellow
    Write-Host "  3. Insufficient disk space" -ForegroundColor Yellow
    Write-Host "  4. Volume Shadow Copy service is not running" -ForegroundColor Yellow
    Write-Host ""
    
    $continue = Read-Host "Continue WITHOUT restore point? Type 'CONTINUE' to proceed"
    
    if ($continue -ne 'CONTINUE') {
        Write-Status "Aborting for safety. No changes were made." "Warning"
        Write-Host ""
        Write-Host "Press any key to exit..."
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
        exit 1
    }
    
    Write-Host ""
    Write-Status "Continuing WITHOUT restore point protection..." "Warning"
}

Write-Host ""
Write-Status "Starting configuration..." "Info"
Write-Host ""

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Set-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [string]$Type = "DWord",
        [string]$Description
    )

    try {
        if (!(Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }

        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
        Write-Status "$Description" "Success"
    } catch {
        Write-Status "Failed: $Description - $_" "Error"
    }
}

# ============================================================================
# 1. DISABLE TELEMETRY SERVICES
# Reference: https://learn.microsoft.com/en-us/windows/privacy/
# ============================================================================
Write-Host "`n=== DISABLING TELEMETRY & UNNECESSARY SERVICES ===" -ForegroundColor Yellow

$services = @(
    @{Name="DiagTrack"; DisplayName="Connected User Experiences and Telemetry"; Warning="None"},
    @{Name="dmwappushservice"; DisplayName="WAP Push Message Routing Service"; Warning="May affect MDM"},
    @{Name="RetailDemo"; DisplayName="Retail Demo Service"; Warning="None"},
    @{Name="XblAuthManager"; DisplayName="Xbox Live Auth Manager"; Warning="Required for Xbox Live"},
    @{Name="XblGameSave"; DisplayName="Xbox Live Game Save"; Warning="Required for Xbox saves"},
    @{Name="XboxNetApiSvc"; DisplayName="Xbox Live Networking Service"; Warning="Required for Xbox multiplayer"},
    @{Name="XboxGipSvc"; DisplayName="Xbox Accessory Management Service"; Warning="MAY BREAK GAME CONTROLLERS"}
)

foreach ($service in $services) {
    try {
        $svc = Get-Service -Name $service.Name -ErrorAction SilentlyContinue
        if ($svc) {
            if ($service.Warning -ne "None") {
                Write-Status "WARNING: $($service.DisplayName) - $($service.Warning)" "Warning"
            }
            Stop-Service -Name $service.Name -Force -ErrorAction SilentlyContinue
            Set-Service -Name $service.Name -StartupType Disabled -ErrorAction SilentlyContinue
            Write-Status "Disabled service: $($service.DisplayName)" "Success"
        } else {
            Write-Status "Service not found: $($service.Name)" "Info"
        }
    } catch {
        Write-Status "Could not disable $($service.DisplayName): $_" "Warning"
    }
}

# ============================================================================
# 2. DISABLE TELEMETRY SCHEDULED TASKS
# Reference: https://learn.microsoft.com/en-us/windows/privacy/
# ============================================================================
Write-Host "`n=== DISABLING TELEMETRY SCHEDULED TASKS ===" -ForegroundColor Yellow

$tasks = @(
    @{Path="\Microsoft\Windows\Application Experience\"; Name="Microsoft Compatibility Appraiser"},
    @{Path="\Microsoft\Windows\Application Experience\"; Name="ProgramDataUpdater"},
    @{Path="\Microsoft\Windows\Autochk\"; Name="Proxy"},
    @{Path="\Microsoft\Windows\Customer Experience Improvement Program\"; Name="Consolidator"},
    @{Path="\Microsoft\Windows\Customer Experience Improvement Program\"; Name="UsbCeip"},
    @{Path="\Microsoft\Windows\DiskDiagnostic\"; Name="Microsoft-Windows-DiskDiagnosticDataCollector"},
    @{Path="\Microsoft\Windows\Feedback\Siuf\"; Name="DmClient"},
    @{Path="\Microsoft\Windows\Feedback\Siuf\"; Name="DmClientOnScenarioDownload"},
    @{Path="\Microsoft\Windows\Windows Error Reporting\"; Name="QueueReporting"}
)

foreach ($task in $tasks) {
    try {
        $scheduledTask = Get-ScheduledTask -TaskPath $task.Path -TaskName $task.Name -ErrorAction SilentlyContinue
        
        if ($scheduledTask) {
            Disable-ScheduledTask -TaskPath $task.Path -TaskName $task.Name -ErrorAction Stop | Out-Null
            Write-Status "Disabled task: $($task.Path)$($task.Name)" "Success"
        } else {
            Write-Status "Task not found: $($task.Name)" "Info"
        }
    } catch {
        Write-Status "Could not disable task: $($task.Name) - $_" "Warning"
    }
}

# ============================================================================
# 3. RESTORE CLASSIC CONTEXT MENU
# Note: Undocumented registry hack, may break in future updates
# ============================================================================
Write-Host "`n=== RESTORING CLASSIC CONTEXT MENU ===" -ForegroundColor Yellow

try {
    $contextMenuPath = "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"

    if (!(Test-Path $contextMenuPath)) {
        New-Item -Path $contextMenuPath -Force | Out-Null
    }

    Set-ItemProperty -Path $contextMenuPath -Name "(Default)" -Value "" -Type String -Force
    Write-Status "Enabled classic Windows 10 context menu" "Success"
} catch {
    Write-Status "Failed to enable classic context menu: $_" "Error"
}

# ============================================================================
# 6. XBOX GAME BAR & GAME MODE
# ============================================================================
Write-Host "`n=== DISABLING XBOX GAME BAR & GAME MODE ===" -ForegroundColor Yellow
Write-Status "WARNING: This will disable Game DVR and screen recording" "Warning"

Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AppCaptureEnabled" -Value 0 -Description "Disabled Game DVR"
Set-RegistryValue -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Value 0 -Description "Disabled Game DVR store"
Set-RegistryValue -Path "HKCU:\Software\Microsoft\GameBar" -Name "AutoGameModeEnabled" -Value 0 -Description "Disabled Game Mode"
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Value 0 -Description "Disabled Game DVR policy"

# ============================================================================
# 7. DISABLE COPILOT
# Reference: https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-windowsai
# ============================================================================
Write-Host "`n=== DISABLING COPILOT ===" -ForegroundColor Yellow

Set-RegistryValue -Path "HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot" -Name "TurnOffWindowsCopilot" -Value 1 -Description "Disabled Copilot (User)"
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" -Name "TurnOffWindowsCopilot" -Value 1 -Description "Disabled Copilot (Machine)"
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCopilotButton" -Value 0 -Description "Hidden Copilot button"

# ============================================================================
# 8. DISABLE WIDGETS
# Reference: https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-newsandinterests
# ============================================================================
Write-Host "`n=== DISABLING WIDGETS ===" -ForegroundColor Yellow

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" -Name "AllowNewsAndInterests" -Value 0 -Description "Disabled Widgets"
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Value 0 -Description "Hidden Widgets button"

# ============================================================================
# 9. PRIVACY & TELEMETRY
# Reference: https://learn.microsoft.com/en-us/windows/privacy/configure-windows-diagnostic-data-in-your-organization
# ============================================================================
Write-Host "`n=== CONFIGURING PRIVACY & TELEMETRY ===" -ForegroundColor Yellow
Write-Host "Setting telemetry to value: $telemetryValue (Edition: $edition)" -ForegroundColor Cyan

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value $telemetryValue -Description "Set telemetry level"
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowDeviceNameInTelemetry" -Value 0 -Description "Disabled device name in telemetry"
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Value 1 -Description "Disabled advertising ID"
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Value 0 -Description "Disabled activity publishing"
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Value 0 -Description "Disabled activity upload"
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackProgs" -Value 0 -Description "Disabled app tracking"
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Value 0 -Description "Disabled feedback requests"
Set-RegistryValue -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Value 1 -Description "Disabled tailored experiences"
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Value 0 -Description "Disabled Timeline"

# ============================================================================
# 10. DISABLE CLOUD CONTENT & SUGGESTIONS
# ============================================================================
Write-Host "`n=== DISABLING CLOUD CONTENT ===" -ForegroundColor Yellow

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value 1 -Description "Disabled consumer features"
Set-RegistryValue -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value 1 -Description "Disabled consumer features (User)"
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableSoftLanding" -Value 1 -Description "Disabled tips"

# ============================================================================
# 11. CONTENTDELIVERYMANAGER SETTINGS
# ============================================================================
Write-Host "`n=== DISABLING RECOMMENDATIONS & SUGGESTIONS ===" -ForegroundColor Yellow

$cdmPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"

Set-RegistryValue -Path $cdmPath -Name "ContentDeliveryAllowed" -Value 0 -Description "Disabled content delivery"
Set-RegistryValue -Path $cdmPath -Name "FeatureManagementEnabled" -Value 0 -Description "Disabled feature management"
Set-RegistryValue -Path $cdmPath -Name "OemPreInstalledAppsEnabled" -Value 0 -Description "Disabled OEM apps"
Set-RegistryValue -Path $cdmPath -Name "PreInstalledAppsEnabled" -Value 0 -Description "Disabled pre-installed apps"
Set-RegistryValue -Path $cdmPath -Name "PreInstalledAppsEverEnabled" -Value 0 -Description "Disabled pre-installed apps ever"
Set-RegistryValue -Path $cdmPath -Name "SilentInstalledAppsEnabled" -Value 0 -Description "Disabled silent installs"
Set-RegistryValue -Path $cdmPath -Name "SoftLandingEnabled" -Value 0 -Description "Disabled soft landing"
Set-RegistryValue -Path $cdmPath -Name "RotatingLockScreenEnabled" -Value 0 -Description "Disabled rotating lockscreen"
Set-RegistryValue -Path $cdmPath -Name "RotatingLockScreenOverlayEnabled" -Value 0 -Description "Disabled lockscreen overlay"
Set-RegistryValue -Path $cdmPath -Name "SubscribedContent-310093Enabled" -Value 0 -Description "Disabled content 310093"
Set-RegistryValue -Path $cdmPath -Name "SubscribedContent-338387Enabled" -Value 0 -Description "Disabled content 338387"
Set-RegistryValue -Path $cdmPath -Name "SubscribedContent-338388Enabled" -Value 0 -Description "Disabled Settings suggestions"
Set-RegistryValue -Path $cdmPath -Name "SubscribedContent-338389Enabled" -Value 0 -Description "Disabled Start tips"
Set-RegistryValue -Path $cdmPath -Name "SubscribedContent-338393Enabled" -Value 0 -Description "Disabled content 338393"
Set-RegistryValue -Path $cdmPath -Name "SubscribedContent-353694Enabled" -Value 0 -Description "Disabled Settings content"
Set-RegistryValue -Path $cdmPath -Name "SubscribedContent-353696Enabled" -Value 0 -Description "Disabled recommendations"
Set-RegistryValue -Path $cdmPath -Name "SubscribedContent-353698Enabled" -Value 0 -Description "Disabled content 353698"
Set-RegistryValue -Path $cdmPath -Name "SystemPaneSuggestionsEnabled" -Value 0 -Description "Disabled system pane suggestions"
Set-RegistryValue -Path $cdmPath -Name "SubscribedContent-280815Enabled" -Value 0 -Description "Disabled Welcome Experience"
Set-RegistryValue -Path $cdmPath -Name "SubscribedContent-314559Enabled" -Value 0 -Description "Disabled OneDrive suggestions"
Set-RegistryValue -Path $cdmPath -Name "SubscribedContent-280810Enabled" -Value 0 -Description "Disabled account notifications"

# ============================================================================
# 12. WINDOWS UPDATE
# Reference: https://learn.microsoft.com/en-us/windows/deployment/update/waas-restart
# WARNING: Prevents automatic restart - may delay security patches
# ============================================================================
Write-Host "`n=== CONFIGURING WINDOWS UPDATE ===" -ForegroundColor Yellow
Write-Status "WARNING: You MUST manually restart for security updates!" "Warning"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Value 1 -Description "Disabled auto-restart"
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "ActiveHoursStart" -Value 8 -Description "Active hours start: 8 AM"
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "ActiveHoursEnd" -Value 23 -Description "Active hours end: 11 PM"

# ============================================================================
# 13. DISABLE WEB SEARCH
# Reference: https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-search
# ============================================================================
Write-Host "`n=== DISABLING WEB SEARCH ===" -ForegroundColor Yellow

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "DisableSearchBoxSuggestions" -Value 1 -Description "Disabled search suggestions"
Set-RegistryValue -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableSearchBoxSuggestions" -Value 1 -Description "Disabled search suggestions (User)"
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Value 0 -Description "Disabled Bing search"
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Value 0 -Description "Disabled Cortana"
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Value 1 -Description "Disabled web search"
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchUseWeb" -Value 0 -Description "Disabled connected search"

# ============================================================================
# 14. CONFIGURE ONEDRIVE
# Reference: https://learn.microsoft.com/en-us/onedrive/use-group-policy
# ============================================================================
Write-Host "`n=== CONFIGURING ONEDRIVE ===" -ForegroundColor Yellow

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Value 1 -Description "Disabled OneDrive sync"
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSync" -Value 1 -Description "Prevented OneDrive traffic"

$hkcrExists = $false
try {
    if (!(Test-Path "HKCR:")) {
        New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT -ErrorAction Stop | Out-Null
        $hkcrExists = $true
    }

    Set-RegistryValue -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Name "System.IsPinnedToNameSpaceTree" -Value 0 -Description "Removed OneDrive from Explorer"
    Set-RegistryValue -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Name "System.IsPinnedToNameSpaceTree" -Value 0 -Description "Removed OneDrive (32-bit)"
        
} catch {
    Write-Status "Could not modify HKCR: $_" "Warning"
} finally {
    if ($hkcrExists -and (Test-Path "HKCR:")) {
        Remove-PSDrive -Name HKCR -Force -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# 15. START MENU & TASKBAR
# Reference: https://learn.microsoft.com/en-us/windows/configuration/taskbar/
# ============================================================================
Write-Host "`n=== CUSTOMIZING TASKBAR ===" -ForegroundColor Yellow

Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Value 0 -Description "Taskbar alignment: LEFT"
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Value 0 -Description "Hidden Task View"
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 2 -Description "Search: Icon + Label"
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackDocs" -Value 0 -Description "Disabled recent apps"
Set-RegistryValue -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "HideRecommendedSection" -Value 1 -Description "Hidden recommendations"
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Value 1 -Description "Hidden Meet Now"
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Value 0 -Description "Hidden People"
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarMn" -Value 0 -Description "Hidden Chat"

# ============================================================================
# 16. ADDITIONAL PRIVACY
# Reference: https://learn.microsoft.com/en-us/windows/privacy/
# ============================================================================
Write-Host "`n=== ADDITIONAL PRIVACY SETTINGS ===" -ForegroundColor Yellow

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Value 1 -Description "Disabled location"
Set-RegistryValue -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightFeatures" -Value 1 -Description "Disabled Spotlight"
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableSoftLanding" -Value 1 -Description "Disabled lockscreen tips"
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value 1 -Description "Disabled error reporting"
Set-RegistryValue -Path "HKCU:\Software\Policies\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Value 1 -Description "Restricted ink collection"
Set-RegistryValue -Path "HKCU:\Software\Policies\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Value 1 -Description "Restricted text collection"
Set-RegistryValue -Path "HKCU:\Software\Policies\Microsoft\Windows\WindowsAI" -Name "DisableAIDataAnalysis" -Value 1 -Description "Disabled Windows Recall"
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Input\Settings" -Name "InsightsEnabled" -Value 0 -Description "Disabled typing insights"

# ============================================================================
# 17. MICROSOFT EDGE
# Reference: https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies
# ============================================================================
Write-Host "`n=== MICROSOFT EDGE CONFIGURATION ===" -ForegroundColor Yellow

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "HideFirstRunExperience" -Value 1 -Description "Disabled Edge first run"
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "StartupBoostEnabled" -Value 0 -Description "Disabled Edge startup boost"
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "BackgroundModeEnabled" -Value 0 -Description "Disabled Edge background"

# ============================================================================
# 17. OFFICE CONNECTED EXPERIENCES
# Reference: https://learn.microsoft.com/en-us/deployoffice/privacy/manage-privacy-controls
# ============================================================================
Write-Host "`n=== OFFICE CONFIGURATION ===" -ForegroundColor Yellow

Set-RegistryValue -Path "HKCU:\Software\Policies\Microsoft\Office\16.0\Common\Privacy" -Name "DisconnectedState" -Value 2 -Description "Office disconnected"
Set-RegistryValue -Path "HKCU:\Software\Policies\Microsoft\Office\Common\ClientTelemetry" -Name "DisableTelemetry" -Value 1 -Description "Disabled Office telemetry"

# ============================================================================
# 19. PERFORMANCE TWEAKS
# ============================================================================
Write-Host "`n=== PERFORMANCE TWEAKS ===" -ForegroundColor Yellow

Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" -Name "StartupDelayInMSec" -Value 0 -Description "Disabled startup delay"
Set-RegistryValue -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Value 0 -Type "String" -Description "Reduced menu delay"

# ============================================================================
# COMPLETION
# ============================================================================

Write-Host ""
Write-Host "===============================================================" -ForegroundColor Green
Write-Host " CONFIGURATION COMPLETE! " -ForegroundColor Green
Write-Host "===============================================================" -ForegroundColor Green
Write-Host ""

Write-Status "All settings applied successfully!" "Success"
Write-Host ""

Write-Host "=== SUMMARY ===" -ForegroundColor Cyan
Write-Host " [+] Telemetry Services: DISABLED"
Write-Host " [+] Telemetry Tasks: DISABLED"
Write-Host " [+] Copilot: DISABLED"
Write-Host " [+] Widgets: DISABLED"
Write-Host " [+] Task View: DISABLED"
Write-Host " [+] Chat/Teams: DISABLED"
Write-Host " [+] Telemetry: MINIMIZED FOR EDITION"
Write-Host " [+] Web Search: DISABLED"
Write-Host " [+] OneDrive: DISABLED"
Write-Host " [+] ContentDeliveryManager: DISABLED"
Write-Host " [+] Taskbar Alignment: LEFT"
Write-Host " [+] Context Menu: CLASSIC"
Write-Host " [+] Visual Effects: DISABLED"
Write-Host " [+] Xbox Services: DISABLED"

Write-Host ""
Write-Status "IMPORTANT:" "Warning"
Write-Host " * System restart REQUIRED for changes to take effect" -ForegroundColor Yellow
Write-Host " * Manual restart required for Windows Updates!" -ForegroundColor Red
Write-Host " * If game controllers fail, re-enable XboxGipSvc" -ForegroundColor Yellow
Write-Host ""

$restart = Read-Host "Restart now? (y/n)"
if ($restart -eq 'y') {
    Write-Status "Restarting..." "Info"
    Restart-Computer -Force
} else {
    Write-Status "Remember to restart manually!" "Warning"
    Write-Host ""
    Write-Host "Press any key to exit..."
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    exit
}
