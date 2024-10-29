#Basic connections setup. Runned once in the terminal (powershell) window before the script usage.
$VCDCred = Get-Credential
$CIServ = Read-Host -Prompt 'Provide CIServer address'
$CITen = Read-Host -Prompt 'Enter Tenant name'
Connect-CIServer -server $CIServ -org $CITen -Credential $VCDCred
#Main script part starts here
Import-CSV "D:\!_Files\VMtoDeploy_VCloud.csv" -Delimiter ';' | ForEach-Object {
#Creating a new VApp from template with VM on board
Write-host (Get-Date -Format "yyyy/MM/dd HH:mm") $_.VMName "Deploying NEW Vapp+VM from template" -ForegroundColor DarkCyan
New-civapp -VAppTemplate $_.Template -Name $_.VMName -Description $_.VMName -OrgVdc $_.OrgVDC  -Server $CIServ | Out-Null
#Set VM in VApp new settins for name
Write-host (Get-Date -Format "yyyy/MM/dd HH:mm") $_.VMName "Reconfiguring VMName and customizations" -ForegroundColor DarkYellow
$VM = Get-CIVM -VApp $_.VMName -OrgVdc $_.OrgVDC -Server $CIServ
($VM.ExtensionData.Section[3]).computername = $_.VMName
$VM.ExtensionData.Section[3].UpdateServerData()
$VM.ExtensionData.name = $_.VMName
$VM.ExtensionData.UpdateServerData()
#Setting up VM customization with one-time password. Later changed by LAPS upon domain join
$GuestCustomization = $VM.ExtensionData.GetGuestCustomizationSection()
$GuestCustomization.AdminPasswordEnabled = $true
$GuestCustomization.AdminPassword = 'Q7k20-RBa!'
$GuestCustomization.AdminPasswordAuto = $false
$GuestCustomization.ChangeSid = $true
$GuestCustomization.ResetPasswordRequired = $false
$GuestCustomization.AdminAutoLogonCount = 0
$GuestCustomization.UpdateServerData()
#Delete Vapp network and connect VM network. "-Connect" shinanigans are made to update old VLAN from template that may hide somewhere in configurations.
Write-host (Get-Date -Format "yyyy/MM/dd HH:mm") $_.VMName "Deleting Network for Vapp" -ForegroundColor DarkYellow
Get-CIVAppNetwork -VApp $_.VMName  -Server $CIServ| Remove-CIVAppNetwork -Confirm:$false | Out-Null
New-CIVAppNetwork -VApp $_.VMName -Direct -ParentOrgVdcNetwork $_.VLAN -Server $CIServ| Out-Null
Write-host (Get-Date -Format "yyyy/MM/dd HH:mm") $_.VMName "Setting up Network on CIVM " -ForegroundColor DarkYellow
Get-OrgVdc $_.OrgVDC -Server $CIServ| Get-CIVApp $_.VMName  -Server $CIServ| Get-CIVM $_.VMName  -Server $CIServ| Get-CINetworkAdapter | Set-CINetworkAdapter -VAppNetwork (Get-OrgVdc $_.OrgVDC -Server $CIServ| Get-CIVApp $_.VMName | Get-CIVappNetwork) -IPaddressAllocationMode Manual -Connected $true -IPAddress $_.IP_Address | Out-Null
Get-OrgVdc $_.OrgVDC -Server $CIServ| Get-CIVApp $_.VMName -Server $CIServ| Get-CIVM $_.VMName -Server $CIServ| Get-CINetworkAdapter -Server $CIServ| Set-CINetworkAdapter -Connected $false | Out-Null
Get-OrgVdc $_.OrgVDC -Server $CIServ| Get-CIVApp $_.VMName -Server $CIServ| Get-CIVM $_.VMName -Server $CIServ| Get-CINetworkAdapter -Server $CIServ| Set-CINetworkAdapter -Connected $true | Out-Null
Write-host (Get-Date -Format "yyyy/MM/dd HH:mm") $_.VMName "Finished VM deployment" -ForegroundColor Green
}
Import-CSV "D:\!_Files\VMtoDeploy_VCloud.csv" -Delimiter ';' | ForEach-Object {
#Search for Memory in ExtensionData and applying the parameter from file multiplied by 1024 as VCloud gets RAM in MB. Curent state of VM is listed to determine error of old VLAN update failure.
Write-host (Get-Date -Format "yyyy/MM/dd HH:mm") $_.VMName "Setting up CPU and RAM - currently" (Get-OrgVdc $_.OrgVDC -Server $CIServ| Get-CIVApp $_.VMName -Server $CIServ| Get-CIVM $_.VMName -Server $CIServ| Get-CINetworkAdapter -Server $CIServ).VM -ForegroundColor Cyan
$VM = Get-CIVM -VApp $_.VMName -OrgVdc $_.OrgVDC -Server $CIServ
$NVRAM = ([System.Convert]::ToDecimal($_.RAM,[cultureinfo]::GetCultureInfo('fr-FR')))*1024
for($i = 0; $i -le $vm.ExtensionData.Section[0].Item.Length; $i++) {
    if($vm.ExtensionData.Section[0].Item[$i].Description.Value -eq "Memory Size"){$vm.ExtensionData.Section[0].Item[$i].VirtualQuantity.Value = $NVRAM}
    elseif ($vm.ExtensionData.Section[0].Item[$i].Description.Value -eq "Number of Virtual CPUs"){$vm.ExtensionData.Section[0].Item[$i].VirtualQuantity.Value = $_.CPU}
}
$vm.ExtensionData.Section[0].UpdateServerData()
###Start VM With Forced Recustomization
Write-host (Get-Date -Format "yyyy/MM/dd HH:mm") $_.VMName "Starting VM with Forced Recustomization" -ForegroundColor DarkYellow
$vm.ExtensionData.Deploy(1,1,0)
##Disable customization
Write-host (Get-Date -Format "yyyy/MM/dd HH:mm") $_.VMName "Disabling Customization" -ForegroundColor DarkYellow
$GuestCustomization = $VM.ExtensionData.GetGuestCustomizationSection()
$GuestCustomization.Enabled = $false
$GuestCustomization.UpdateServerData()
Write-host (Get-Date -Format "yyyy/MM/dd HH:mm") $_.VMName "Finished VM Hardware setup and launch" -ForegroundColor Green
}
Write-host (Get-Date -Format "yyyy/MM/dd HH:mm") $_.VMName "Disconnecting from CIServer" -ForegroundColor Green
Disconnect-CIServer -Server * -Confirm:$false
