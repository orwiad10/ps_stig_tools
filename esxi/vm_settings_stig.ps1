﻿<#
.SYNOPSIS
    This script will set each applicable STIG checks for the VM portion of the ESXi 6.5 STIG. 
.PARAMETER hostip
    This is one or more host IP address to run the STIG on.
.EXAMPLE
    .\vm_settings_stig.ps1 -hostip 127.0.0.1
    This runs on one host
.EXAMPLE
    .\vm_settings_stig.ps1 -hostip 127.0.0.1, 127.0.0.2
    This runs on multiple hosts
.TODO
    Convert the entire stig setting block in to a background job so all the VMs get ran async vs one by one.
.NOTES
    Date:   20201013    
#>

param(
    [parameter(Mandatory=$true, HelpMessage = "Enter the IP for The Host You Want To Run VM STIGs On.")]
    [validatescript({$_ -match [ipaddress]$_})]
    [string[]]$Hostip
)

#open a file window so we open a file, multi select is on
Function Open-File($initialDirectory,$filter){   
    
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null

    $OpenFileDialog                  = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.initialDirectory = $initialDirectory
    $OpenFileDialog.filter           = $filter
    $OpenFileDialog.Multiselect      = $false
    $OpenFileDialog.ShowDialog()     | Out-Null
    $OpenFileDialog.filenames
}

function decode_string {
    param([string]$encstr)
    $bytes  = [convert]::FromBase64String($encstr)
    $decstr = [System.Text.Encoding]::Unicode.GetString($bytes)
    return $decstr
}

if(!(Test-Connection $hostip -Count 1 -Quiet)){
    Write-Verbose "CANT CONNECT TO HOST CABLE DIRECTLY TO RACK AND RUN AGAIN!" -Verbose
    break
}

Write-host "Starting VM STIG"
$pass = decode_string -encstr "encoded_string" | ConvertTo-SecureString -AsPlainText -Force #use any credential solution you want
$cred = new-object -typename System.Management.Automation.PSCredential("root", $pass)

#extract powercli
if(![bool](test-path "C:\Windows\System32\WindowsPowerShell\v1.0\Modules\VMware.DeployAutomation")){
    
    $file = open-file -filter "ZIP (*.zip)| *.zip" -initialDirectory "$env:USERPROFILE\desktop" -message "Open PowerCLI .zip"
    
    #Set the directory to extract the zip file to.
    $zippath    = $file
    $extractDir = "C:\windows\system32\WindowsPowerShell\v1.0\Modules"
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zippath,$extractDir)
}

if(!(get-module VMware.VimAutomation.Common)){
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    import-module vmware.vimautomation.core -WarningAction SilentlyContinue -erroraction SilentlyContinue -Force | out-null
}

set-PowerCliConfiguration -InvalidCertificateAction Ignore -Confirm:$false | out-null

foreach($h in $hostip){

    Write-host "Connect To Host"
    try{
        $global:DefaultVIServers | ForEach-Object{Disconnect-VIServer $_.name -Confirm:$false -ErrorAction SilentlyContinue} | out-null
    }catch{}

    Connect-VIServer $h -Credential $cred -erroraction SilentlyContinue | out-null

    foreach($v in (get-vm)){

        Write-Host "STIG-ing " $v.name
    
        #94563
        try{
            $v | New-AdvancedSetting -Name isolation.tools.copy.disable -Value true -Confirm:$false -Force | Out-Null
        }catch{
            $v | Get-AdvancedSetting -Name isolation.tools.copy.disable | Set-AdvancedSetting -Value true -Confirm:$false -Force | Out-Null
        }

        #94565
        try{
            $v | New-AdvancedSetting -Name isolation.tools.dnd.disable -Value true -Confirm:$false -Force | Out-Null
        }catch{
            $v | Get-AdvancedSetting -Name isolation.tools.dnd.disable | Set-AdvancedSetting -Value true -Confirm:$false -Force | Out-Null
        }

        #94567
        try{
            $v | New-AdvancedSetting -Name isolation.tools.setGUIOptions.enable -Value false -Confirm:$false -Force | Out-Null
        }catch{
            $v | Get-AdvancedSetting -Name isolation.tools.setGUIOptions.enable | Set-AdvancedSetting -Value false -Confirm:$false -Force | Out-Null
        }

        #94569
        try{
            $v | New-AdvancedSetting -Name isolation.tools.paste.disable -Value true -Confirm:$false -Force | Out-Null
        }catch{
            $v | Get-AdvancedSetting -Name isolation.tools.paste.disable | Set-AdvancedSetting -Value true -Confirm:$false -Force | Out-Null
        }

        #94571
        try{
            $v | New-AdvancedSetting -Name isolation.tools.diskShrink.disable -Value true -Confirm:$false -Force | Out-Null
        }catch{
            $v | Get-AdvancedSetting -Name isolation.tools.diskShrink.disable | Set-AdvancedSetting -Value true -Confirm:$false -Force | Out-Null
        }

        #94573
        try{
            $v | New-AdvancedSetting -Name isolation.tools.diskWiper.disable -Value true -Confirm:$false -Force | Out-Null
        }catch{
            $v | Get-AdvancedSetting -Name isolation.tools.diskWiper.disable | Set-AdvancedSetting -Value true -Confirm:$false -Force | Out-Null
        }

        #94575
        #$v | Get-HardDisk | Set-HardDisk -Persistence IndependentPersistent
        #$v | Get-HardDisk | Set-HardDisk -Persistence Persistent

        #94577
        try{
            $v | New-AdvancedSetting -Name isolation.tools.hgfsServerSet.disable -Value true -Confirm:$false -Force | Out-Null
        }catch{
            $v | Get-AdvancedSetting -Name isolation.tools.hgfsServerSet.disable | Set-AdvancedSetting -Value true -Confirm:$false -Force | Out-Null
        }

        #94579
        try{
            $v | New-AdvancedSetting -Name isolation.tools.ghi.autologon.disable -Value true -Confirm:$false -Force | Out-Null
        }catch{
            $v | Get-AdvancedSetting -Name isolation.tools.ghi.autologon.disable | Set-AdvancedSetting -Value true -Confirm:$false -Force | Out-Null 
        }  

        #94581
        try{
            $v | New-AdvancedSetting -Name isolation.tools.ghi.launchmenu.change -Value true -Confirm:$false -Force | Out-Null
        }catch{ 
            $v | Get-AdvancedSetting -Name isolation.tools.ghi.launchmenu.change | Set-AdvancedSetting -Value true -Confirm:$false -Force | Out-Null
        }

        #94583
        try{
            $v | New-AdvancedSetting -Name isolation.tools.memSchedFakeSampleStats.disable -Value true -Confirm:$false -Force | Out-Null
        }catch{
            $v | Get-AdvancedSetting -Name isolation.tools.memSchedFakeSampleStats.disable | Set-AdvancedSetting -Value true -Confirm:$false -Force | Out-Null
        }

        #94585
        try{
            $v | New-AdvancedSetting -Name isolation.tools.ghi.protocolhandler.info.disable -Value true -Confirm:$false -Force | Out-Null
        }catch{
            $v | Get-AdvancedSetting -Name isolation.tools.ghi.protocolhandler.info.disable | Set-AdvancedSetting -Value true -Confirm:$false -Force | Out-Null
        }

        #94593
        try{
            $v | New-AdvancedSetting -Name isolation.ghi.host.shellAction.disable -Value true -Confirm:$false -Force | Out-Null
        }catch{
            $v | Get-AdvancedSetting -Name isolation.ghi.host.shellAction.disable | Set-AdvancedSetting -Value true -Confirm:$false -Force | Out-Null
        } 

        #94595
        try{
            $v | New-AdvancedSetting -Name isolation.tools.ghi.trayicon.disable -Value true -Confirm:$false -Force | Out-Null
        }catch{
            $v | Get-AdvancedSetting -Name isolation.tools.ghi.trayicon.disable | Set-AdvancedSetting -Value true -Confirm:$false -Force | Out-Null
        }

        #94597
        try{
            $v | New-AdvancedSetting -Name isolation.tools.unity.disable -Value true -Confirm:$false -Force | Out-Null
        }catch{
            $v | Get-AdvancedSetting -Name isolation.tools.unity.disable | Set-AdvancedSetting -Value true -Confirm:$false -Force | Out-Null
        }

        #94599
        try{
            $v | New-AdvancedSetting -Name isolation.tools.unityInterlockOperation.disable -Value true -Confirm:$false -Force | Out-Null
        }catch{
            $v | Get-AdvancedSetting -Name isolation.tools.unityInterlockOperation.disable | Set-AdvancedSetting -Value true -Confirm:$false -Force | Out-Null
        }

        #94601
        try{
            $v | New-AdvancedSetting -Name isolation.tools.unity.push.update.disable -Value true -Confirm:$false -Force | Out-Null
        }catch{
            $v | Get-AdvancedSetting -Name isolation.tools.unity.push.update.disable | Set-AdvancedSetting -Value true -Confirm:$false -Force | Out-Null
        }

        #94603
        try{
            $v | New-AdvancedSetting -Name isolation.tools.unity.taskbar.disable -Value true -Confirm:$false -Force | Out-Null
        }catch{
            $v | Get-AdvancedSetting -Name isolation.tools.unity.taskbar.disable | Set-AdvancedSetting -Value true -Confirm:$false -Force | Out-Null
        }

        #94605
        try{
            $v | New-AdvancedSetting -Name isolation.tools.unityActive.disable -Value true -Confirm:$false -Force | Out-Null
        }catch{
            $v | Get-AdvancedSetting -Name isolation.tools.unityActive.disable | Set-AdvancedSetting -Value true -Confirm:$false -Force | Out-Null
        }

        #94607
        try{ 
            $v | New-AdvancedSetting -Name isolation.tools.unity.windowContents.disable -Value true -Confirm:$false -Force | Out-Null
        }catch{
            $v | Get-AdvancedSetting -Name isolation.tools.unity.windowContents.disable | Set-AdvancedSetting -Value true -Confirm:$false -Force | Out-Null
        }

        #94609
        try{
            $v | New-AdvancedSetting -Name isolation.tools.vmxDnDVersionGet.disable -Value true -Confirm:$false -Force | Out-Null
        }catch{
            $v | Get-AdvancedSetting -Name isolation.tools.vmxDnDVersionGet.disable | Set-AdvancedSetting -Value true -Confirm:$false -Force | Out-Null
        } 

        #94611
        try{
            $v | New-AdvancedSetting -Name isolation.tools.guestDnDVersionSet.disable -Value true -Confirm:$false -Force | Out-Null
        }catch{
            $v | Get-AdvancedSetting -Name isolation.tools.guestDnDVersionSet.disable | Set-AdvancedSetting -Value true -Confirm:$false -Force | Out-Null
        }

        #94613
        $v | Get-FloppyDrive | Remove-FloppyDrive -Confirm:$false | Out-Null

        #94615
        $v | Get-CDDrive | Set-CDDrive -NoMedia -Confirm:$false | Out-Null

        #94617
        if($v| Where-Object {$_.ExtensionData.Config.Hardware.Device.DeviceInfo.Label -match "parallel"}){
            Write-Verbose "Log In To Vsphere Web Client And Remove Parallel Device From $v"
        }

        #94619
        if($v | Where-Object {$_.ExtensionData.Config.Hardware.Device.DeviceInfo.Label -match "serial"}){
            Write-Verbose "Log In To Vsphere Web Client And Remove Serial Device From $v"
        }

        #94621
        $v | Get-USBDevice | Remove-USBDevice -Confirm:$false | Out-Null

        #94623
        try{
            $v | New-AdvancedSetting -Name RemoteDisplay.maxConnections -Value 1 -Confirm:$false -Force | Out-Null
        }catch{
            $v | Get-AdvancedSetting -Name RemoteDisplay.maxConnections | Set-AdvancedSetting -Value 1 -Confirm:$false -Force | Out-Null
        }

        #94625
        try{
            $v | New-AdvancedSetting -Name RemoteDisplay.vnc.enabled -Value false -Confirm:$false -Force | Out-Null
        }catch{
            $v | Get-AdvancedSetting -Name RemoteDisplay.vnc.enabled | Set-AdvancedSetting -Value false -Confirm:$false -Force | Out-Null
        }

        #94627
        try{
            $v | New-AdvancedSetting -Name tools.setinfo.sizeLimit -Value 1048576 -Confirm:$false -Force | Out-Null
        }catch{
            $v | Get-AdvancedSetting -Name tools.setinfo.sizeLimit | Set-AdvancedSetting -Value 1048576 -Confirm:$false -Force | Out-Null
        }

        #94629
        try{
            $v | New-AdvancedSetting -Name isolation.device.connectable.disable -Value true -Confirm:$false -Force | Out-Null
        }catch{
            $v | Get-AdvancedSetting -Name isolation.device.connectable.disable | Set-AdvancedSetting -Value true -Confirm:$false -Force | Out-Null
        }

        #94631
        try{
            $v | New-AdvancedSetting -Name tools.guestlib.enableHostInfo -Value false -Confirm:$false -Force | Out-Null
        }catch{
            $v | Get-AdvancedSetting -Name tools.guestlib.enableHostInfo | Set-AdvancedSetting -Value false -Confirm:$false -Force | Out-Null
        }

        #94633
        $v | Get-AdvancedSetting -Name sched.mem.pshare.salt | Remove-AdvancedSetting -Confirm:$false | Out-Null

        #94635
        if($null -ne ($v | Get-AdvancedSetting -Name "ethernet*.filter*.name*")){
            Write-Verbose "Log In To Vsphere Web Client And Remove Ethernet Filters From Advanced Settings On $v"
        }

        #94647
        try{
            $v | New-AdvancedSetting -Name tools.guest.desktop.autolock -Value true -Confirm:$false -Force | Out-Null
        }catch{
            $v | Get-AdvancedSetting -Name tools.guest.desktop.autolock | Set-AdvancedSetting -Value true -Confirm:$false -Force | Out-Null
        }

        #94649
        try{
            $v | New-AdvancedSetting -Name mks.enable3d -Value false -Confirm:$false -Force | Out-Null
        }catch{
            $v | Get-AdvancedSetting -Name mks.enable3d | Set-AdvancedSetting -Value false -Confirm:$false -Force | Out-Null
        }
    }
}