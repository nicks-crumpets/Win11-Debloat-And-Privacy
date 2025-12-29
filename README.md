# Windows 11 Privacy and Performance Configuration Script

## What This Script Does

This PowerShell script automatically configures Windows 11 to disable telemetry, remove bloatware, improve privacy, and enhance system performance. It modifies registry settings and system configurations to give you more control over your Windows 11 installation.

The script operates in two modes:
1. Apply Settings Mode - Makes all configuration changes to your system
2. Verify Settings Mode - Checks which settings have been applied without making changes

## Why This Is Useful

Windows 11 includes many features that collect data, show advertisements, and consume system resources. These features include:

- Telemetry and diagnostic data collection sent to Microsoft
- Automatic installation of suggested apps and games
- Advertising ID tracking across applications
- Copilot AI assistant integration
- Widgets with news and advertisements
- Xbox services running even if you don't game
- Web search in the Start menu
- OneDrive integration and sync
- Activity history tracking and upload
- Personalized ads and recommendations

This script disables these features, giving you:

- Improved privacy by stopping data collection
- Better performance by disabling unnecessary services
- Reduced network usage from background processes
- Less clutter in the Start menu and taskbar
- More control over system behavior
- Faster boot times
- Reduced disk usage

## What Changes Are Made

### Telemetry and Data Collection
- Disables Connected User Experiences and Telemetry service
- Disables diagnostic data collection (set to minimum for your Windows edition)
- Disables advertising ID
- Disables activity history tracking and publishing
- Disables feedback requests
- Disables Windows Error Reporting
- Disables typing and handwriting data collection

### Services Disabled
- DiagTrack (Connected User Experiences and Telemetry)
- dmwappushservice (WAP Push Message Routing)
- RetailDemo (Retail Demo Service)
- XblAuthManager (Xbox Live Auth Manager)
- XblGameSave (Xbox Live Game Save)
- XboxNetApiSvc (Xbox Live Networking Service)
- XboxGipSvc (Xbox Accessory Management Service)

### Scheduled Tasks Disabled
- Microsoft Compatibility Appraiser
- ProgramDataUpdater
- Consolidator
- UsbCeip
- DiskDiagnosticDataCollector
- DmClient and DmClientOnScenarioDownload
- QueueReporting

### User Interface Changes
- Restores classic Windows 10 right-click context menu
- Moves taskbar alignment to the left (Windows 10 style)
- Disables transparency effects
- Disables window animations
- Disables taskbar animations
- Hides Task View button
- Hides Chat/Teams icon
- Hides Meet Now button
- Hides People icon
- Sets search box to icon and label mode
- Disables recently added apps tracking

### Features Disabled
- Windows Copilot AI assistant
- Widgets (News and Interests)
- Windows Spotlight on lock screen
- Tips and suggestions
- App recommendations in Start menu
- Automatic app installations
- OneDrive file sync
- Web search in Start menu
- Cortana
- Xbox Game Bar and Game Mode
- Game DVR and screen recording
- Windows Recall AI (24H2 and newer)
- Location tracking

### Content Delivery Manager (Bloatware Prevention)
Disables all automatic content delivery including:
- Suggested apps in Start menu
- Tips and tricks notifications
- App suggestions in Settings
- Pre-installed OEM apps
- Silent app installations
- Lock screen suggestions
- Welcome Experience content

### Windows Update Configuration
- Prevents automatic restart when users are logged on
- Sets active hours (8 AM to 11 PM by default)
- Note: You must manually restart to install security updates

### Privacy Settings
- Disables all ContentDeliveryManager suggestions
- Disables Windows consumer features
- Disables cloud content synchronization
- Disables tailored experiences based on diagnostic data
- Disables Timeline feature
- Restricts handwriting and text input data collection

### Microsoft Edge Configuration
- Disables first run experience
- Disables startup boost
- Disables background mode

### Office Configuration
- Sets Office to disconnected state
- Disables Office telemetry

### Performance Optimizations
- Disables startup delay for programs
- Reduces menu show delay
- Sets visual effects to best performance

## System Requirements

- Windows 11 (Pro, Enterprise, or Education recommended)
- Administrator privileges
- PowerShell 5.1 or higher
- System Restore enabled (recommended)

## Compatibility Notes

### Windows 11 Home Edition
Approximately 40 percent of the settings in this script will NOT work on Windows Home edition because it lacks Group Policy support. Registry-based settings will still apply, but machine-level policies under HKLM:\SOFTWARE\Policies\ will be ignored.

### Windows 11 Pro Edition
Most settings will work. Telemetry can only be set to "Basic" level (value 1), not completely disabled.

### Windows 11 Enterprise/Education Edition
All settings fully supported. Telemetry can be set to "Security" level (value 0), effectively disabling it.

## How to Use

1. Right-click the script file and select "Run with PowerShell"
   OR
2. Open PowerShell as Administrator
3. Navigate to the script location
4. Run: .\Win11-Debloat-And-Privacy.ps1

The script will:
1. Check for administrator privileges (and request elevation if needed)
2. Show a comprehensive warning screen
3. Detect your Windows edition
4. Ask you to confirm (type YES)
5. Offer two modes: Apply Settings or Verify Settings
6. Create a system restore point (if applying settings)
7. Apply all configuration changes
8. Show a summary of changes
9. Offer to restart the computer

## Verification Mode

Run the script and select option 2 to check which settings have been applied without making any changes. This is useful for:
- Confirming the script worked correctly
- Checking if Windows updates reverted any settings
- Auditing your system configuration
- Troubleshooting issues

## How to Undo Changes

### Option 1: System Restore
1. Open Control Panel
2. Go to System > System Protection
3. Click System Restore
4. Select the restore point created before running this script
5. Follow the wizard to restore

### Option 2: Reset Specific Settings
The script creates registry changes. You can manually reverse them by:
- Setting disabled services back to Manual or Automatic
- Re-enabling scheduled tasks through Task Scheduler
- Deleting registry keys created by the script
- Changing registry values back to their defaults

### Option 3: Windows Reset
Settings > System > Recovery > Reset this PC
(This will reinstall Windows while optionally keeping your files)

---

## WARNINGS AND IMPORTANT INFORMATION

### CRITICAL SECURITY WARNING
This script disables automatic restart after Windows Updates. This means security patches will NOT be applied until you manually restart your computer. Delaying restarts can leave your system vulnerable to security exploits.

YOU MUST MANUALLY RESTART YOUR COMPUTER AFTER WINDOWS UPDATES.

### GAME CONTROLLER WARNING
The script disables the Xbox Accessory Management Service (XboxGipSvc). This service is used by:
- Xbox controllers (wired and wireless)
- PlayStation controllers when used on PC
- Generic USB and Bluetooth game controllers
- Some racing wheels and flight sticks

If your game controllers stop working after running this script, you need to re-enable the XboxGipSvc service:
1. Open Services (services.msc)
2. Find "Xbox Accessory Management Service"
3. Set Startup type to "Manual" or "Automatic"
4. Click Start
5. Restart your computer

### GAME DVR AND SCREEN RECORDING WARNING
This script disables Game DVR, Game Bar, and Game Mode. You will lose the ability to:
- Record gameplay using Windows Game Bar (Win+G)
- Take screenshots with Game Bar
- Use Game Mode for performance optimization
- Stream to Xbox or other devices

If you need these features, do not run this script or manually re-enable them after.

### ONEDRIVE WARNING
OneDrive file sync will be completely disabled. Any files stored only in OneDrive will not sync to your computer. Make sure you have local copies of important files before running this script.

### WINDOWS HOME EDITION WARNING
If you are running Windows 11 Home edition, approximately 40 percent of this script will not work because Home edition does not support Group Policy settings. The script will run without errors, but many machine-level policies will be silently ignored by Windows.

Settings that WILL work on Home:
- User-level registry settings (HKCU)
- Service disabling
- Scheduled task disabling
- Visual effects and interface changes

Settings that WILL NOT work on Home:
- Machine-level telemetry policies (HKLM:\SOFTWARE\Policies\)
- Group Policy configurations
- Enterprise-only privacy settings
- Some Windows Update policies

### SYSTEM STABILITY WARNING
Modifying system registry keys and disabling services can potentially cause system instability. While this script uses well-documented settings, there is always a risk when making system-level changes.

Always create a restore point before running (the script attempts to do this automatically).

### WINDOWS UPDATE WARNING
Some settings modified by this script may be reset or overridden by:
- Major Windows feature updates (like 24H2 to 25H1)
- Cumulative updates in some cases
- Group Policy changes if you're on a domain

You may need to run this script again after major Windows updates.

### COMPATIBILITY WARNING
This script is designed for Windows 11 versions 24H2 and 25H2. It may work on earlier versions but has not been tested. Some registry keys and services may not exist on older Windows 11 builds.

### PERFORMANCE WARNING
While this script is designed to improve performance, disabling certain services may have unintended consequences:
- Some Windows features may stop working
- Certain apps may behave unexpectedly
- System diagnostics and troubleshooting tools may be limited
- Microsoft support may require you to re-enable telemetry for troubleshooting

### BACKUP WARNING
This script relies on Windows System Restore for reverting changes. System Restore has limitations:
- Only one restore point can be created per 24 hours
- Restore points may be deleted automatically if disk space is low
- System Restore may fail in some situations
- Restore points do not back up personal files

It is recommended to have a full system backup (using third-party software or Windows Backup) before running this script.

### ENTERPRISE ENVIRONMENT WARNING
If you are on a corporate or enterprise network:
- Your IT department's Group Policies may override these settings
- Running this script may violate company policies
- Domain-joined computers may have settings managed centrally
- Contact your IT department before running this script

### LEGAL DISCLAIMER
This script is provided as-is without any warranty. The authors are not responsible for:
- Data loss
- System instability
- Security vulnerabilities
- Conflicts with other software
- Violation of terms of service
- Any other issues arising from use of this script

Use at your own risk. Always maintain current backups of important data.

### TELEMETRY CLARIFICATION
Even with this script applied:
- Windows Home: Minimum telemetry is "Enhanced" (cannot be fully disabled)
- Windows Pro: Minimum telemetry is "Basic" (cannot be fully disabled)
- Windows Enterprise/Education: Telemetry can be set to "Security" (effectively disabled)

Setting telemetry values lower than your edition allows will result in Windows ignoring the setting and using the minimum allowed value.

### ACTIVATION AND LICENSING
This script does not affect Windows activation or licensing. It only modifies privacy and performance settings. All changes are made to an activated, licensed copy of Windows 11.

---

## Additional Information

### What This Script Does NOT Do
- Does not remove Windows components or features
- Does not uninstall built-in Windows apps
- Does not modify Windows Defender or security settings
- Does not disable Windows Update itself (only auto-restart)
- Does not affect third-party software
- Does not change network or firewall settings
- Does not modify file permissions
- Does not delete user data

### Restore Point Limitations
The script attempts to create a system restore point before making changes. However:
- Windows limits restore point creation to once per 24 hours
- If a restore point was already created today, the script cannot create another
- The script will ask for confirmation before proceeding without a restore point
- System Restore may be disabled on your system by default

### Future Updates
Windows 11 is updated regularly. Microsoft may:
- Add new telemetry features
- Change registry key locations
- Modify how services work
- Override these settings in updates

This script may need updates to remain effective against new Windows 11 versions.

### Source and Verification
This script is based on:
- Official Microsoft Group Policy documentation
- Microsoft Learn documentation
- PowerShell documentation
- CIS Microsoft Windows 11 Benchmark
- Community-verified registry tweaks

All settings are documented and reversible.

---

## Support and Issues

If you experience issues after running this script:

1. Use System Restore to revert changes
2. Check if specific services need to be re-enabled
3. Review the verification mode output to see what was changed
4. Consult Windows Event Viewer for error messages
5. Re-enable telemetry temporarily if you need Microsoft support

Remember: This script makes significant system changes. Only use it if you understand the implications and accept the risks.

---

## Version Information

Script Version: 1.0
Date: December 2025
Tested On: Windows 11 24H2, Windows 11 25H2
PowerShell Version: 5.1 and higher

---

Last Updated: December 29, 2025
