﻿<#
.SYNOPSIS
    This script will set all the ESXi 6.7 STIG settings.
.PARAMETER Hostip
    This is ip or list of ip's of hosts you want to stig.
.EXAMPLE
    .\esxi_6.7_stig.ps1 -hostip 127.0.0.1
    This STIGs one host
.EXAMPLE
    .\esxi_6.7_stig.ps1 -hostip 127.0.0.1, 127.0.0.2
    This STIGs multiple hosts
.TODO
    Add background jobs.
.NOTES
    Date:   20210910   
#>

param(
    [parameter(Mandatory=$true, HelpMessage = "Enter the IP for The Server You Want To STIG.")]
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

Write-host "Starting ESXI 6.7 STIG"
$Pswd  = decode_string -encstr "encoded_string" #can be done any way you want
$cred  = new-object -typename System.Management.Automation.PSCredential("root", ($pswd | ConvertTo-SecureString -AsPlainText -Force))

#extract powercli
if(![bool](test-path "C:\Windows\System32\WindowsPowerShell\v1.0\Modules\VMware.DeployAutomation")){
    
    $file = open-file -filter "ZIP (*.zip)| *.zip" -initialDirectory "$env:USERPROFILE\desktop" -message "Open PowerCLI .zip"
    
    #Set the directory to extract the zip file to.
    $zippath    = $file
    $extractDir = "C:\windows\system32\WindowsPowerShell\v1.0\Modules"
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zippath,$extractDir)
}

foreach($h in $hostip){
    
    try{
        $global:DefaultVIServers | ForEach-Object {Disconnect-VIServer $_.name -Confirm:$false -ErrorAction SilentlyContinue} | out-null
    }catch{}

    if(!(get-module VMware.VimAutomation.Common)){
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
        import-module vmware.vimautomation.core -WarningAction SilentlyContinue -erroraction SilentlyContinue -Force | out-null
    }

    set-PowerCliConfiguration -InvalidCertificateAction Ignore -Confirm:$false | out-null

    Connect-VIServer $h -Credential $cred -erroraction SilentlyContinue -WarningAction SilentlyContinue | out-null

    #start SSH service
    Write-host "Start SSH"
    $sshService = Get-VmHostService -VMHost $h | Where-Object {$_.Key -eq “TSM-SSH”} 
    Start-VMHostService -HostService $sshService -Confirm:$false | out-null

    #set up the esxcli object
    #syslog var is also used for the coredump setting
    $esxcli  = Get-EsxCli -VMHost (get-vmhost -Name $h) -WarningAction SilentlyContinue
    $vmhost  = (get-vmhost -Name $h)
    
    #esxi

    #239267
    if($esxcli.system.security.fips140.ssh.get.invoke().enabled -ne $true){
        $arguments = $esxcli.system.security.fips140.ssh.set.CreateArgs()
        $arguments.enable = $true
        $esxcli.system.security.fips140.ssh.set.Invoke($arguments)
    }

    #239287
    if((Get-VMHost $vmhost | Get-AdvancedSetting -Name Security.PasswordHistory).value -ne 5){
        Get-VMHost $vmhost | Get-AdvancedSetting -Name Security.PasswordHistory | Set-AdvancedSetting -Value 5 -Confirm:$false
    }

    #239306
    #vmotion not enabled

    #239308
    #iSCSI is not used

    #239329
    if((Get-VMHost $vmhost | Get-AdvancedSetting -Name UserVars.SuppressShellWarning).Value -ne 0){
        Get-VMHost $vmhost | Get-AdvancedSetting -Name UserVars.SuppressShellWarning | Set-AdvancedSetting -Value "0" -confirm:$false
    }

    #vm
    foreach($v in (get-vm)){
        
        #242469
        $enctype = ($v | Select-Object Name, @{Name="vMotionEncrpytion";Expression={$_.extensiondata.config.MigrateEncryption}}).vMotionEncrpytion
        
        if($enctype -ne "opportunistic"){
            $VMView                   = $v | Get-View
            $Config                   = New-Object VMware.Vim.VirtualMachineConfigSpec
            $Config.MigrateEncryption = New-Object VMware.Vim.VirtualMachineConfigSpecEncryptedVMotionModes
            $Config.MigrateEncryption = "opportunistic"
            $VMView.ReconfigVM($Config)
        }
    }
}