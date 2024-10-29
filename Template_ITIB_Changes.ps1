<#Checking if host is workstation and applying WS fixes#>
$ErrorActionPreference = 'SilentlyContinue'
Write-Host "Starting preparation script execution" -ForegroundColor DarkCyan

if (((Get-CimInstance -ClassName Win32_OperatingSystem).ProductType) -eq '1'){

Write-Host "Disabling TPM or CPU checks to allow further updates" -ForegroundColor Yellow
    New-Item -path 'HKLM:\SYSTEM\Setup\MoSetup' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\Setup\MoSetup' -Name 'AllowUpgradesWithUnsupportedTPMOrCPU' -Value 1 -PropertyType DWord -force | Out-Null

Write-Host "EnablingLabConfig for Win11 TCM/CPU Checks bypass" -ForegroundColor Yellow
    New-Item -path 'HKLM:\SYSTEM\Setup\LabConfig' -Force | Out-Null
    Set-ItemProperty -Path 'HKLM:\SYSTEM\Setup\LabConfig' -Name 'BypassSecureBootCheck' -Value '1' -Type DWord -Force | Out-Null
    Set-ItemProperty -Path 'HKLM:\SYSTEM\Setup\LabConfig' -Name 'BypassTPMCheck' -Value '1' -Type DWord -Force | Out-Null
    
<#Loading default users registry hive#>
reg load HKU\DFLT_ED 'C:\Users\Default\NTUSER.DAT' | Out-Null
Write-Host "Cleaning Start Panel" -ForegroundColor Yellow
    New-Item -Path 'REGISTRY::HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\' -Name Advanced | Out-Null
    New-Item -Path 'REGISTRY::HKEY_USERS\DFLT_ED\Software\Microsoft\Windows\CurrentVersion\Explorer\' -Name Advanced | Out-Null
    foreach ($panvalue in 'TaskbarDa','TaskbarMn','ShowTaskViewButton','Start_TrackDocs')
        {foreach ($panpath in 'REGISTRY::HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced','HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced','REGISTRY::HKEY_USERS\DFLT_ED\Software\Microsoft\Windows\CurrentVersion\Explorer\')
        {Set-ItemProperty -Path $panpath -Name $panvalue -Value 0 -Force | Out-Null} 
        }
Write-Host "Blocking preinstalled apps" -ForegroundColor Yellow
foreach ($apppath1 in 'REGISTRY::HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\','HKCU:\Software\Microsoft\Windows\CurrentVersion\','REGISTRY::HKEY_USERS\DFLT_ED\Software\Microsoft\Windows\CurrentVersion\'){
    foreach ($appkey1 in 'Feeds','ContentDeliveryManager'){
        New-Item -Path $apppath1 -Name $appkey1 -Force  | Out-Null}}
foreach ($appkey2 in 'REGISTRY::HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Feeds','REGISTRY::HKEY_USERS\DFLT_ED\Software\Microsoft\Windows\CurrentVersion\Feeds','HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds'){
    foreach ($appval2 in 'ShellFeedsTaskbarContentUpdateMode','ShellFeedsTaskbarOpenOnHover'){Set-ItemProperty -Path $appkey2 -Name $appval2 -Value 0 -Force  | Out-Null}}
foreach ($appkey3 in 'REGISTRY::HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\','REGISTRY::HKEY_USERS\DFLT_ED\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\','HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\'){
    foreach ($appval3 in 'FeatureManagementAllowed','FeatureManagementEnabled','OemPreInstalledAppsEnabled','PreInstalledAppsEnabled','PreInstalledAppsEverEnabled','SilentInstalledAppsEnabled','SubscribedContent-338388Enabled','SubscribedContent-338389Enabled','SubscribedContent-88000326Enabled','SubscribedContentEnabled'){Set-ItemProperty -Path $appkey3 -Name $appval3 -Value 0 -Force  | Out-Null}}
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\' -Name CloudContent | Out-Null
foreach ($appval4 in 'DisableCloudOptimizedContent','DisableConsumerAccountStateContent','DisableWindowsConsumerFeatures'){Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name $appval4 -Value 1 -Force  | Out-Null}

Write-Host "Disabling Windows Copilot" -ForegroundColor Yellow
foreach ($apppath5 in 'REGISTRY::HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Windows\WindowsCopilot','HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot','REGISTRY::HKEY_USERS\DFLT_ED\Software\Policies\Microsoft\Windows\WindowsCopilot'){
    New-Item -path $apppath5 -Force  | Out-Null
    New-ItemProperty -Path $apppath5 -Name 'TurnOffWindowsCopilot' -Value 1 -PropertyType DWord -force | Out-Null
}
Write-Host "Disabling privacy settings for new user" -ForegroundColor Yellow
New-Item -path 'HKLM:\Software\Policies\Microsoft\Windows\OOBE' -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\OOBE' -Name 'DisablePrivacyExperience' -Value 1 -Force  | Out-Null

Write-Host "Fixing unusable start-menu icons if Citrix is installed" -ForegroundColor Yellow
New-Item -Path 'HKLM:\SOFTWARE\Citrix\CtxHook' -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Citrix\CtxHook' -Name 'ExcludedImageNames' -Value 'StartmenuExperienceHost.exe' -Type String -Force | Out-Null

Write-Host "Install AD DA RSAT capability" -ForegroundColor Yellow
Add-WindowsCapability -online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 -AllUsers | Out-Null

Write-Host "Remove Notepad++ appX package to allow sysprep" -ForegroundColor Yellow
Get-AppxPackage -Name *NotepadPlusPlus* | Remove-AppxPackage -AllUsers | Out-Null

# Might be a bad idea...
$killister = @("xbox","people","zune","bing","edge","gaming","phone","cloudex","clipcha","solitaire","office","outlook","cortana","onedrive")
foreach ($deleter in ((Get-AppxPackage | Where-object {$prname = $_.name; $killister | ForEach-Object {if ($prname -like "*$_*"){return $true}} }).PackageFullName)) {Remove-AppxPackage -AllUsers -Package $deleter -ErrorAction SilentlyContinue}
foreach ($deleter in ((Get-AppxProvisionedPackage -Online | Where-object {$prname = $_.PackageName; $killister | ForEach-Object {if ($prname -like "*$_*"){return $true}} }).PackageFullName)) {Remove-AppxProvisionedPackage -Online -PackageName $deleter -AllUsers -ErrorAction SilentlyContinue}
Get-AppxPackage | Where-object {$prname = $_.name; $killister | ForEach-Object {if ($prname -like "*$_*"){return $true}} } | Remove-AppxPackage -ErrorAction SilentlyContinue

<#UNLoading default users registry hive#>
$null = REG UNLOAD HKEY_Users\DFLT_ED
}

<#Applying default All-OS fixes#>
Write-Host "Disabling IPv6 registry" -ForegroundColor Yellow
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name 'DisabledComponents' -Value 255 -PropertyType DWord -force | Out-Null

Write-Host "Removing 3DES Cipher and TLS1.0/1.1" -ForegroundColor Yellow
foreach ($T in 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA','TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA','TLS_RSA_WITH_AES_256_GCM_SHA384','TLS_RSA_WITH_AES_128_GCM_SHA256','TLS_RSA_WITH_AES_256_CBC_SHA256','TLS_RSA_WITH_AES_128_CBC_SHA256','TLS_RSA_WITH_AES_256_CBC_SHA','TLS_RSA_WITH_AES_128_CBC_SHA','TLS_RSA_WITH_3DES_EDE_CBC_SHA') {Disable-TlsCipherSuite -name $T -ErrorAction SilentlyContinue | Out-Null}

Write-Host "Disabling TLS1.0 & TLS1.1 through registry edits" -ForegroundColor Yellow
$TLSPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
$KEYs = '\TLS 1.0\Client','\TLS 1.0\Server','\TLS 1.1\Client','\TLS 1.1\Server','\SSL 2.0\Client','\SSL 2.0\Server','\SSL 3.0\Client','\SSL 3.0\Server'
foreach ($KEY in $KEYs) {
    New-item -Path $TLSPath$KEY -force | Out-Null
    New-ItemProperty -Path $TLSPath$KEY -Name Enabled -value 0 -PropertyType DWord  -force | Out-Null
    New-ItemProperty -Path $TLSPath$KEY -Name DisabledByDefault -value 1 -PropertyType DWord -force | Out-Null
}

Write-Host "Enabling SMB Signing" -ForegroundColor Yellow
Foreach ($par in 'EnableSecuritySignature','RequireSecuritySignature') {Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name $par -Value 1 -PassThru | Out-Null}

Write-Host "Disabling TCP timestamp" -ForegroundColor Yellow
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name Tcp1323Opts -Value 0 -force -PassThru | Out-Null
netsh int tcp set global timestamps=disabled | Out-Null

Write-Host "Disabling ICMP timestamp responses" -ForegroundColor Yellow
netsh firewall set icmpsetting 13 disable | Out-Null

Write-Host "Disabling Print Spooler" -ForegroundColor Yellow
Get-Service "spooler" | Set-Service -StartupType Disabled
Stop-Service "spooler" -Force

Write-Host "Setting LSA registry value" -ForegroundColor Yellow
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LMCompatibilityLevel -Value 5 -force -PassThru | Out-Null

Write-Host "Setting NTLM check level registry values" -ForegroundColor Yellow
Foreach ($param in 'NtlmMinClientSec','NtlmMinServerSec') {Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name $param -Value 20080000  | Out-Null}

Write-Host "Disabling NETBIOS wintrust config using registry" -ForegroundColor Yellow
New-Item -Path 'HKLM:\Software\Microsoft\Cryptography\Wintrust\' -Name Config -Force | Out-Null
New-ItemProperty -path 'HKLM:\Software\Microsoft\Cryptography\Wintrust\Config' -Name EnableCertPaddingCheck -Value 1 -PropertyType String -Force | Out-Null
New-Item -Path 'HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\' -Name Config -Force | Out-Null
New-ItemProperty -path 'HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config' -Name EnableCertPaddingCheck -Value 1 -PropertyType String -Force | Out-Null
$ErrorActionPreference = 'Continue'

Write-Host 'Enabling Telnet Client' -ForegroundColor Yellow
Enable-WindowsOptionalFeature -Online -FeatureName TelnetClient -NoRestart | Out-Null
<#
Here you can wipe IP, logs, powershell read line logs and shutdown a machine uf press "Y". Disabled for further experimentation.
#>

if ((read-host "Kill IP, logs and shutdown? [Y]es : [N]o") -eq "y") {
$killipaddr = (Get-NetIPAddress -InterfaceIndex ((Get-NetAdapter -name "eth*" | Where-object Status -like "up").ifindex)).IPAddress
$killifindex = (Get-NetAdapter -name "eth*" | Where-object Status -like "up").ifindex
$killgate = (Get-WmiObject -Class Win32_IP4RouteTable | Where-Object { $_.destination -eq '0.0.0.0' -and $_.mask -eq '0.0.0.0'}).nexthop
Write-Host 'ReTrimming Disk' -ForegroundColor Yellow
Get-Disk | Where-Object {$_.ProvisioningType -eq 'Thin'} | Get-Partition | Where-Object {$_.Type -in ('IFS', 'Basic','Extended')} | Get-Volume | Optimize-Volume -Analyze -ReTrim -SlabConsolidate
<#
if wiping IP fails, stop logs wipe and shutdown
#>
try {Remove-NetIPAddress -IPAddress $killipaddr -DefaultGateway $killgate -Confirm:$false
Set-DnsClientServerAddress -ResetServerAddresses -InterfaceIndex $killifindex
Set-NetIPInterface -Dhcp Enabled -InterfaceIndex $killifindex}
catch {$killiperror = 1; Write-Host "There are errors on IP wipe. Please fix. Shutdown and logwipe postponed" -ForegroundColor Red}
if ($killiperror -ne 1) {
    Clear-Content ((Get-PSReadlineOption).HistorySavePath)
    Start-Process powershell.exe -ArgumentList 'wevtutil el | Foreach-Object {wevtutil cl "$_"}' -Wait -NoNewWindow
    [Microsoft.PowerShell.PSConsoleReadLine]::ClearHistory()
    Remove-Item $PSCommandPath -Force
    Stop-Computer -Force
}
}
