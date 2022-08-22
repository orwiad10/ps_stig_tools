<#
.SYNOPSIS
    This script will set all the ESXi 6.5 STIG settings.
.PARAMETER Hostip
    This is ip or list of ip's of hosts you want to stig.
.EXAMPLE
    .\esxi_6.5_stig.ps1 -hostip 127.0.0.1
    This STIGs one host
.EXAMPLE
    .\esxi_6.5_stig.ps1 -hostip 127.0.0.1, 127.0.0.2
    This STIGs multiple hosts
.TODO
    Add background jobs.
.NOTES
    Date:   20201013    
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

Write-host "Starting ESXI STIG"
#plink setup "plinko rename because mcafee"
$Pswd  = decode_string -encstr "encodedstring"  #use any credential solution 
$plink = "C:\Program Files\PuTTY\plinko.exe"
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
    
    write-host "STIGing " $h
    Write-host "Connect To Host"

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

    #3 methods to accept the rsa key automatically. 1: echo y to plink. 2: -batch. 3: redirect all error streams to stdout, assign to a var and regex the thumbprint out then specify it with the hostkey flag for each command.
    #idk which actually works so we gon do them all.
    Write-host "Attempt To Get Server Thumbprint"
    $prethumb = Write-Output y | & $plink -v -batch -pw $pswd root@$($h) "grep -i '^Banner' /etc/ssh/sshd_config" 4>&1 3>&1 2>&1
    $thumb    = [regex]::Match($prethumb,"(?>[0-9a-f]{2}:){15}[0-9a-f]{2}").value

    #only used for vcenter servers
    <#
    #93949
    $level    = "lockdownNormal"
    $vmhost   = Get-VMHost | get-view
    $lockdown = Get-View $vmhost.ConfigManager.HostAccessManager
    $lockdown.ChangeLockdownMode($level)

    #93951
    $vmhost | Get-AdvancedSetting -Name DCUI.Access | Set-AdvancedSetting -Value "root" -confirm:$false | out-null

    #93953
    $vmhost = Get-VMHost | Get-View
    $lockdown = Get-View $vmhost.ConfigManager.HostAccessManager
    $lockdown.QueryLockdownExceptions()
    #>

    #93955
    Write-host "93955"
    $syslog  = switch($h.split(".")[3].length){
        2 {"155.22.$($h.split(".")[2]).13"}
        3 {"155.22.$($h.split(".")[2]).133"}
    }

    $vmhost | Get-AdvancedSetting -Name Syslog.global.logHost | Set-AdvancedSetting -Value $syslog -Confirm:$false | out-null

    #93957
    Write-host "93957"
    $vmhost | Get-AdvancedSetting -Name Security.AccountLockFailures | Set-AdvancedSetting -Value 3 -Confirm:$false | out-null

    #93959
    Write-host "93959"
    $vmhost | Get-AdvancedSetting -Name Security.AccountUnlockTime | Set-AdvancedSetting -Value 900 -Confirm:$false | out-null

    #93961
    Write-host "93961"
    $welcomemessage = @"
    {bgcolor:black} {/color}{align:left}{bgcolor:black}{color:yellow}{hostname}, {ip}{/color}{/bgcolor}{/align}
    {bgcolor:black} {/color}{align:left}{bgcolor:black}{color:yellow}{esxproduct} {esxversion}{/color}{/bgcolor}{/align}
    {bgcolor:black} {/color}{align:left}{bgcolor:black}{color:yellow}{memory} RAM{/color}{/bgcolor}{/align}
    {bgcolor:black} {/color}{align:left}{bgcolor:black}{color:white} {/color}{/bgcolor}{/align}
    {bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black} {/color}{/bgcolor}{/align}
    {bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black} You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By {/color}{/bgcolor}{/align}
    {bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black} using this IS (which includes any device attached to this IS), you consent to the following conditions: {/color}{/bgcolor}{/align}
    {bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black} {/color}{/bgcolor}{/align}
    {bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black} - The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited {/color}{/bgcolor}{/align}
    {bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black} to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law {/color}{/bgcolor}{/align}
    {bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black} enforcement (LE), and counterintelligence (CI) investigations. {/color}{/bgcolor}{/align}
    {bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black} {/color}{/bgcolor}{/align}
    {bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black} - At any time, the USG may inspect and seize data stored on this IS. {/color}{/bgcolor}{/align}
    {bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black} {/color}{/bgcolor}{/align}
    {bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black} - Communications using, or data stored on, this IS are not private, are subject to routine monitoring, {/color}{/bgcolor}{/align}
    {bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black} interception, and search, and may be disclosed or used for any USG-authorized purpose. {/color}{/bgcolor}{/align}
    {bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black} {/color}{/bgcolor}{/align}
    {bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black} - This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not {/color}{/bgcolor}{/align}
    {bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black} for your personal benefit or privacy. {/color}{/bgcolor}{/align}
    {bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black} {/color}{/bgcolor}{/align}
    {bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black} - Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching {/color}{/bgcolor}{/align}
    {bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black} or monitoring of the content of privileged communications, or work product, related to personal representation {/color}{/bgcolor}{/align}
    {bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black} or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work {/color}{/bgcolor}{/align}
    {bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black} product are private and confidential. See User Agreement for details. {/color}{/bgcolor}{/align}
    {bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black} {/color}{/bgcolor}{/align}
    {bgcolor:black} {/color}{bgcolor:dark-grey}{color:black} {/color}{/bgcolor}
    {bgcolor:black} {/color}{bgcolor:dark-grey}{color:black} {/color}{/bgcolor}
    {bgcolor:black} {/color}{bgcolor:dark-grey}{color:black} {/color}{/bgcolor}
    {bgcolor:black} {/color}{bgcolor:dark-grey}{color:black} {/color}{/bgcolor}
    {bgcolor:black} {/color}{align:left}{bgcolor:dark-grey}{color:white}[F2] Accept Conditions and Customize System / View Logs{/align}{align:right} [F12] Accept Conditions and Shut Down/Restart {bgcolor:black} {/color}{/color}{/bgcolor}{/align}
    {bgcolor:black} {/color}{bgcolor:dark-grey}{color:black} {/color}{/bgcolor}
"@

    try{
        Get-AdvancedSetting -Entity $vmhost -Name Annotations.WelcomeMessage | Set-AdvancedSetting -Value $welcomemessage -Confirm:$false -erroraction stop | out-null
    }catch{
        Write-Verbose -Verbose "Verify Welcome Banner in The Web Console"
    }

    #93963
    Write-host "93963"
    try{
        Get-AdvancedSetting -Entity $vmhost -Name Config.Etc.issue | Set-AdvancedSetting -Value $welcomemessage -confirm:$false | out-null
    }catch{
        Write-Verbose -Verbose "Verify Etc Issue"
    }

    #93965
    Write-host "93965"
    #all ssh commands are roughly the same so this is the only one with comments.
    #redirect all error streams to null so we can capture the output to a var and compare
    $banner = & $plink -v -batch -pw $pswd root@$($h) -hostkey $thumb 'grep -i "^Banner" /etc/ssh/sshd_config' 4>$null 3>$null 2>$null

    #if our value doesnt equal the check the we use sed -i to re-find it and replace it with the correct value.
    if($banner -ne "Banner /etc/issue"){
        & $plink -v -batch -pw $pswd root@$($h) -hostkey $thumb "sed -i 's/^Banner.*/Banner /etc/issue/g' /etc/ssh/sshd_config" 4>$null 3>$null 2>$null 1>$null
    }

    #93967
    Write-host "93967"
    $cipher = & $plink -v -batch -pw $pswd root@$($h) -hostkey $thumb 'grep -i "^Ciphers" /etc/ssh/sshd_config' 4>$null 3>$null 2>$null

    if($cipher -ne "Ciphers aes128-ctr,aes192-ctr,aes256-ctr"){
        & $plink -v -batch -pw $pswd root@$($h) -hostkey $thumb "sed -i 's/^Ciphers.*/Ciphers aes128-ctr,aes192-ctr,aes256-ctr/g' /etc/ssh/sshd_config" 4>$null 3>$null 2>$null 1>$null
    }

    #93969
    Write-host "93969"
    $proto = & $plink -v -batch -pw $pswd root@$($h) -hostkey $thumb 'grep -i "^Protocol" /etc/ssh/sshd_config' 4>$null 3>$null 2>$null

    #can be a $null return so add a case for this. probably a non-default unlike the other sshd_config checks.
    if($proto -ne "Protocol 2" -and $null -ne $proto){
        & $plink -v -batch -pw $pswd root@$($h) -hostkey $thumb "sed -i 's/^Protocol.*/Protocol 2/g' /etc/ssh/sshd_config" 4>$null 3>$null 2>$null 1>$null
    }elseif($null -eq $proto){
        & $plink -v -batch -pw $pswd root@$($h) -hostkey $thumb "echo 'Protocol 2' >> /etc/ssh/sshd_config" 4>$null 3>$null 2>$null 1>$null
    }

    #93971
    Write-host "93971"
    $rhost = & $plink -v -batch -pw $pswd root@$($h) -hostkey $thumb 'grep -i "^IgnoreRhosts" /etc/ssh/sshd_config' 4>$null 3>$null 2>$null

    if($rhost -ne "IgnoreRhosts yes"){
        & $plink -v -batch -pw $pswd root@$($h) -hostkey $thumb "sed -i 's/^IgnoreRhosts.*/IgnoreRhosts yes/g' /etc/ssh/sshd_config" 4>$null 3>$null 2>$null 1>$null
    }

    #93973
    Write-host "93973"
    $hosta = & $plink -v -batch -pw $pswd root@$($h) -hostkey $thumb 'grep -i "^HostbasedAuthentication" /etc/ssh/sshd_config' 4>$null 3>$null 2>$null

    if($hosta -ne "HostbasedAuthentication no"){
        & $plink -v -batch -pw $pswd root@$($h) -hostkey $thumb "sed -i 's/^HostbasedAuthentication.*/HostbasedAuthentication no/g' /etc/ssh/sshd_config" 4>$null 3>$null 2>$null 1>$null
    }

    #93975
    Write-host "93975"
    #stig says no root ssh but we need it, so do the opposite and set it yes if its blank. cant ssh unless its yes or blank so....
    $permit = & $plink -v -batch -pw $pswd root@$($h) -hostkey $thumb 'grep -i "^PermitRootLogin" /etc/ssh/sshd_config' 4>$null 3>$null 2>$null

    if($permit -ne "PermitRootLogin yes" -and $null -ne $permit){
        & $plink -v -batch -pw $pswd root@$($h) -hostkey $thumb "sed -i 's/^PermitRootLogin.*/PermitRootLogin yes/g' /etc/ssh/sshd_config" 4>$null 3>$null 2>$null 1>$null
    }elseif($null -eq $permit){
        & $plink -v -batch -pw $pswd root@$($h) -hostkey $thumb "echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config" 4>$null 3>$null 2>$null 1>$null
    }

    #93977
    Write-host "93977"
    $emptyp = & $plink -v -batch -pw $pswd root@$($h) -hostkey $thumb 'grep -i "^PermitEmptyPasswords" /etc/ssh/sshd_config' 4>$null 3>$null 2>$null

    if($emptyp -ne "PermitEmptyPasswords no"){
        & $plink -v -batch -pw $pswd root@$($h) -hostkey $thumb "sed -i 's/^PermitEmptyPasswords.*/PermitEmptyPasswords no/g' /etc/ssh/sshd_config" 4>$null 3>$null 2>$null 1>$null
    }

    #93979
    Write-host "93979"
    $penv = & $plink -v -batch -pw $pswd root@$($h) -hostkey $thumb 'grep -i "^PermitUserEnvironment" /etc/ssh/sshd_config' 4>$null 3>$null 2>$null

    if($penv -ne "PermitUserEnvironment no"){
        & $plink -v -batch -pw $pswd root@$($h) -hostkey $thumb "sed -i 's/^PermitUserEnvironment.*/PermitUserEnvironment no/g' /etc/ssh/sshd_config" 4>$null 3>$null 2>$null 1>$null
    }

    #93981
    Write-host "93981"
    $macs = & $plink -v -batch -pw $pswd root@$($h) -hostkey $thumb 'grep -i "^MACs" /etc/ssh/sshd_config' 4>$null 3>$null 2>$null

    if($macs -ne "MACs hmac-sha1,hmac-sha2-256,hmac-sha2-512"){
        & $plink -v -batch -pw $pswd root@$($h) -hostkey $thumb "sed -i 's/^MACs.*/MACs hmac-sha1,hmac-sha2-256,hmac-sha2-512/g' /etc/ssh/sshd_config" 4>$null 3>$null 2>$null 1>$null
    }

    #93983
    Write-host "93983"
    $gssapi = & $plink -v -batch -pw $pswd root@$($h) -hostkey $thumb 'grep -i "^GSSAPIAuthentication" /etc/ssh/sshd_config' 4>$null 3>$null 2>$null

    if($gssapi -ne "GSSAPIAuthentication no"){
        & $plink -v -batch -pw $pswd root@$($h) -hostkey $thumb "sed -i 's/^GSSAPIAuthentication.*/GSSAPIAuthentication no/g' /etc/ssh/sshd_config" 4>$null 3>$null 2>$null 1>$null
    }

    #93985
    Write-host "93985"
    $kerb = & $plink -v -batch -pw $pswd root@$($h) -hostkey $thumb 'grep -i "^KerberosAuthentication" /etc/ssh/sshd_config' 4>$null 3>$null 2>$null

    if($kerb -ne "KerberosAuthentication no"){
        & $plink -v -batch -pw $pswd root@$($h) -hostkey $thumb "sed -i 's/^KerberosAuthentication.*/KerberosAuthentication no/g' /etc/ssh/sshd_config" 4>$null 3>$null 2>$null 1>$null
    }

    #93987
    Write-host "93987"
    $strict = & $plink -v -batch -pw $pswd root@$($h) -hostkey $thumb 'grep -i "^StrictModes" /etc/ssh/sshd_config' 4>$null 3>$null 2>$null

    if($strict -ne "StrictModes yes"){
        & $plink -v -batch -pw $pswd root@$($h) -hostkey $thumb "sed -i 's/^StrictModes.*/StrictModes yes/g' /etc/ssh/sshd_config" 4>$null 3>$null 2>$null 1>$null
    }

    #93989
    Write-host "93989"
    $comp = & $plink -v -batch -pw $pswd root@$($h) -hostkey $thumb 'grep -i "^Compression" /etc/ssh/sshd_config' 4>$null 3>$null 2>$null

    if($comp -ne "Compression no"){
        & $plink -v -batch -pw $pswd root@$($h) -hostkey $thumb "sed -i 's/^Compression.*/Compression no/g' /etc/ssh/sshd_config" 4>$null 3>$null 2>$null 1>$null
    }

    #93991
    Write-host "93991"
    $gate = & $plink -v -batch -pw $pswd root@$($h) -hostkey $thumb 'grep -i "^GatewayPorts" /etc/ssh/sshd_config' 4>$null 3>$null 2>$null

    if($gate -ne "GatewayPorts no"){
        & $plink -v -batch -pw $pswd root@$($h) -hostkey $thumb "sed -i 's/^GatewayPorts.*/GatewayPorts no/g' /etc/ssh/sshd_config" 4>$null 3>$null 2>$null 1>$null
    }

    #93993
    Write-host "93993"
    $x11 = & $plink -v -batch -pw $pswd root@$($h) -hostkey $thumb 'grep -i "^X11Forwarding" /etc/ssh/sshd_config' 4>$null 3>$null 2>$null

    if($x11 -ne "X11Forwarding no"){
        & $plink -v -batch -pw $pswd root@$($h) -hostkey $thumb "sed -i 's/^X11Forwarding.*/X11Forwarding no/g' /etc/ssh/sshd_config" 4>$null 3>$null 2>$null 1>$null
    }

    #93995
    Write-host "93995"
    $accept = & $plink -v -batch -pw $pswd root@$($h) -hostkey $thumb 'grep -i "^AcceptEnv" /etc/ssh/sshd_config' 4>$null 3>$null 2>$null

    if($accept -ne "AcceptEnv" -and $null -ne $accept){
        & $plink -v -batch -pw $pswd root@$($h) -hostkey $thumb "sed -i 's/^AcceptEnv.*/AcceptEnv/g' /etc/ssh/sshd_config" 4>$null 3>$null 2>$null 1>$null
    }elseif($null -eq $accept){
        & $plink -v -batch -pw $pswd root@$($h) -hostkey $thumb "echo 'AcceptEnv' >> /etc/ssh/sshd_config" 4>$null 3>$null 2>$null 1>$null
    }

    #93997
    Write-host "93997"
    $tun = & $plink -v -batch -pw $pswd root@$($h) -hostkey $thumb 'grep -i "^PermitTunnel" /etc/ssh/sshd_config' 4>$null 3>$null 2>$null

    if($tun -ne "PermitTunnel no"){
        & $plink -v -batch -pw $pswd root@$($h) -hostkey $thumb "sed -i 's/^PermitTunnel.*/PermitTunnel no/g' /etc/ssh/sshd_config" 4>$null 3>$null 2>$null 1>$null
    }

    #93999
    Write-host "93999"
    $max = & $plink -v -batch -pw $pswd root@$($h) -hostkey $thumb 'grep -i "^ClientAliveCountMax" /etc/ssh/sshd_config' 4>$null 3>$null 2>$null

    if($max -ne "ClientAliveCountMax 3"){
        & $plink -v -batch -pw $pswd root@$($h) -hostkey $thumb "sed -i 's/^ClientAliveCountMax.*/ClientAliveCountMax 3/g' /etc/ssh/sshd_config" 4>$null 3>$null 2>$null 1>$null
    }

    #94001
    Write-host "94001"
    $cli = & $plink -v -batch -pw $pswd root@$($h) -hostkey $thumb 'grep -i "^ClientAliveInterval" /etc/ssh/sshd_config' 4>$null 3>$null 2>$null

    if($cli -ne "ClientAliveInterval 200"){
        & $plink -v -batch -pw $pswd root@$($h) -hostkey $thumb "sed -i 's/^ClientAliveCountMax.*/ClientAliveInterval 200/g' /etc/ssh/sshd_config" 4>$null 3>$null 2>$null 1>$null
    }

    #94003
    Write-host "94003"
    $ses = & $plink -v -batch -pw $pswd root@$($h) -hostkey $thumb 'grep -i "^MaxSessions" /etc/ssh/sshd_config' 4>$null 3>$null 2>$null

    if($ses -ne "MaxSessions 1"){
        & $plink -v -batch -pw $pswd root@$($h) -hostkey $thumb "sed -i 's/^MaxSessions.*/MaxSessions 1' /etc/ssh/sshd_config" 4>$null 3>$null 2>$null 1>$null
    }

    #94005
    Write-host "94005"
    $auth = & $plink -v -batch -pw $pswd root@$($h) -hostkey $thumb 'ls -la /etc/ssh/keys-root/authorized_keys' 4>$null 3>$null 2>$null

    if($null -ne $auth){
        & $plink -v -batch -pw $pswd root@$($h) -hostkey $thumb "rm /etc/ssh/keys-root/authorized_keys" 4>$null 3>$null 2>$null 1>$null
    }

    #94007
    Write-host "94007"
    $vmhost | Get-AdvancedSetting -Name Config.HostAgent.log.level | Set-AdvancedSetting -Value "info" -confirm:$false  | out-null

    #94009
    Write-host "94009"
    $vmhost | Get-AdvancedSetting -Name Security.PasswordQualityControl | Set-AdvancedSetting -Value "similar=deny retry=3 min=disabled,disabled,disabled,disabled,15" -confirm:$false  | out-null

    #94011 & 94013
    Write-host "94011 & 94013"
    #copy /dev/null to the file to empty it out.
    & $plink -v -batch -pw $pswd root@$($h) -hostkey $thumb "cp /dev/null /etc/pam.d/passwd" 4>$null 3>$null 2>$null 1>$null

    #each line of the file is set as a here-string to super escape the $ sign in the file path.
    #not sure is if spacing is strict but why risk it eh?
    $passpam1 = @'
    password   requisite    /lib/security/$ISA/pam_passwdqc.so retry=3 min=disabled,disabled,disabled,7,7
'@
    $passpam2 = @'
    password   sufficient   /lib/security/$ISA/pam_unix.so use_authtok nullok shadow sha512 remember=5
'@
    $passpam3 = @'
    password   required     /lib/security/$ISA/pam_deny.so
'@

    #foreach of my passpam variables
    foreach($v in ((Get-Variable | Where-Object {$_.Name -like "passpam*"}).Value)){
        #echo each the here-strings in to the file
        & $plink -v -batch -pw $pswd root@$($h) -hostkey $thumb "echo '$($v)' >> /etc/pam.d/passwd" 4>$null 3>$null 2>$null 1>$null
    }

    #94015
    Write-host "94015"
    $vmhost | Get-AdvancedSetting -Name Config.HostAgent.plugins.solo.enableMob | Set-AdvancedSetting -Value false -confirm:$false  | out-null

    #94021
    Write-host "94021"
    #we dont join hosts to the domain to dodge other stig checks. 
    #$vmhost | Get-VMHostAuthentication | Set-VMHostAuthentication -JoinDomain -Domain "domain.do.main" -Credential (get-credential -Message "Enter Credentials" -UserName "domain\") -confirm:$false

    #94029
    Write-host "94029"
    $vmhost | Get-AdvancedSetting -Name UserVars.ESXiShellInteractiveTimeOut | Set-AdvancedSetting -Value 600 -confirm:$false  | out-null

    #94031
    Write-host "94031"
    $vmhost | Get-AdvancedSetting -Name UserVars.ESXiShellTimeOut | Set-AdvancedSetting -Value 600 -confirm:$false  | out-null

    #94033
    Write-host "94033"
    $vmhost | Get-AdvancedSetting -Name UserVars.DcuiTimeOut | Set-AdvancedSetting -Value 600 -confirm:$false  | out-null

    #94035
    Write-host "94035"
    [array]$coredumppart = ($esxcli.system.coredump.partition.list() | Where-Object {$_.active -eq $true -and $_.configured -eq $true}).name

    if($coredumppart){
        if(!$esxcli.system.coredump.partition.set($null,$coredumppart[0],$null,$null)){
            Write-Host "Core Dump Partition Not Set"
        }
    }

    [array]$vmk = ($vmhost | Get-VMHostNetworkAdapter | Where-Object {$_.ip.length -gt 0} | Sort-Object).name

    $esxcli.system.coredump.network.set($null,$vmk[0],$null,$syslog,"6500") | out-null
    $esxcli.system.coredump.network.set($true) | Out-Null

    #94037
    Write-host "94037"
    #https://docs.vmware.com/en/VMware-vSphere/6.5/com.vmware.vsphere.install.doc/GUID-9F67DB52-F469-451F-B6C8-DAE8D95976E7.html
    #"Only the /scratch directory on the local file system is persistent across reboots."
    #quote from vmware, the default is persistent

    $globlogdit = ($esxcli.system.syslog.config.get()).LocalLogOutputIsPersistent

    if($globlogdit){
    }else{
        "FINDING"
    }

    #94039
    write-host "94039"
    $NTPServer = switch($h.split(".")[3].length){
        2 {"155.22.$($h.split(".")[2]).123"}
        3 {"155.22.$($h.split(".")[2]).174"}
    }

    $vmhost | Add-VMHostNTPServer -NtpServer $ntpserver -erroraction silentlycontinue | Out-Null
    $vmhost | Get-VMHostService | Where-Object {$_.Label -eq "NTP Daemon"} | Set-VMHostService -Policy On -Confirm:$false | Out-Null
    $vmhost | Get-VMHostService | Where-Object {$_.Label -eq "NTP Daemon"} | Start-VMHostService -Confirm:$false | Out-Null

    #94041
    Write-host "94041"
    $esxcli.software.acceptance.Set("PartnerSupported") | Out-Null

    #94053
    Write-host "94053"
    $hostsnmp = Get-VMHostSnmp
    Set-VMHostSnmp -HostSnmp $hostsnmp -Enabled:$true -AddTarget:$true -TargetCommunity "com_name" -TargetPort 555 -TargetHost 111.222.333.444 | out-null

    #94057
    Write-host "94057"
    $vmhost | Get-AdvancedSetting -Name Mem.ShareForceSalting | Set-AdvancedSetting -Value 2 -Confirm:$false | Out-Null

    #94059
    Write-host "94059"
    $esxcli.network.firewall.set($null, $false) | out-null
    $firewallruleset = ($esxcli.network.firewall.ruleset.list()).name
    $172             = "172.0.0.1"
    $17217           = "172.0.10.0/24"

    foreach($f in $firewallruleset){
        try{$esxcli.network.firewall.ruleset.set($false,$true,$f) | out-null}catch{}
        try{$esxcli.network.firewall.ruleset.allowedip.add($17217,$f) | out-null}catch{}
        try{$esxcli.network.firewall.ruleset.allowedip.add("192.168.0.0/17",$f) | out-null}catch{}
        try{$esxcli.network.firewall.ruleset.allowedip.add($172,$f) | out-null}catch{}
    }

    $esxcli.network.firewall.refresh() | out-null
    $esxcli.network.firewall.set($null, $true) | out-null

    #94061
    Write-host "94061"
    $vmhost | Get-VMHostFirewallDefaultPolicy | Set-VMHostFirewallDefaultPolicy -AllowIncoming $false -AllowOutgoing $false -Confirm:$false | out-null

    #94063
    Write-host "94063"
    $vmhost | Get-AdvancedSetting -Name Net.BlockGuestBPDU | Set-AdvancedSetting -Value 1 -Confirm:$false | out-null

    #94065
    Write-host "94065"
    $vmhost | Get-VirtualSwitch | Get-SecurityPolicy | Set-SecurityPolicy -ForgedTransmits $false | Out-Null
    $vmhost | Get-VirtualPortGroup | Get-SecurityPolicy | Set-SecurityPolicy -ForgedTransmitsInherited $true | Out-Null

    #94067
    Write-host "94067"
    $vmhost | Get-VirtualSwitch | Get-SecurityPolicy | Set-SecurityPolicy -MacChanges $false | Out-Null
    $vmhost | Get-VirtualPortGroup | Get-SecurityPolicy | Set-SecurityPolicy -MacChangesInherited $true | Out-Null

    #94069
    Write-host "94069"
    $vmhost | Get-VirtualSwitch | Get-SecurityPolicy | Set-SecurityPolicy -AllowPromiscuous $false  | Out-Null
    $vmhost | Get-VirtualPortGroup | Get-SecurityPolicy | Set-SecurityPolicy -AllowPromiscuousInherited $true  | Out-Null

    #94071
    Write-host "94071"
    $vmhost | Get-AdvancedSetting -Name Net.DVFilterBindIpAddress | Set-AdvancedSetting -Value "" -Confirm:$false | Out-Null

    #94075
    Write-host "94075"
    $vlans = $vmhost | Get-VirtualPortGroup | Select-Object Name, VLanID

    if($vlans.vlanid -contains "4095"){
        write-host "Remove vlan tag on " $(($vlans | Where-Object {$_.vlanid -eq 4095}).name)
    }

    #94481
    Write-host "94481"
    & $plink -v -batch -pw $pswd root@$($h) -hostkey $thumb 'cp -f /etc/sfcb/sfcb.cfg /etc/sfcb/sfcb.cfg.orig' 4>$null 3>$null 2>$null 1>$null
    & $plink -v -batch -pw $pswd root@$($h) -hostkey $thumb 'grep -v "enableTLS" /etc/sfcb/sfcb.cfg.orig>/etc/sfcb/sfcb.cfg' 4>$null 3>$null 2>$null 1>$null
    & $plink -v -batch -pw $pswd root@$($h) -hostkey $thumb 'echo enableTLSv1: false>>/etc/sfcb/sfcb.cfg' 4>$null 3>$null 2>$null 1>$null
    & $plink -v -batch -pw $pswd root@$($h) -hostkey $thumb 'echo enableTLSv1_1: false>>/etc/sfcb/sfcb.cfg' 4>$null 3>$null 2>$null 1>$null
    & $plink -v -batch -pw $pswd root@$($h) -hostkey $thumb 'echo enableTLSv1_2: true>>/etc/sfcb/sfcb.cfg' 4>$null 3>$null 2>$null 1>$null
    & $plink -v -batch -pw $pswd root@$($h) -hostkey $thumb '/etc/init.d/sfcbd-watchdog restart' 4>$null 3>$null 2>$null 1>$null

    #94483
    Write-host "94483"
    $vmhost | Get-AdvancedSetting -Name UserVars.ESXiVPsDisabledProtocols | Set-AdvancedSetting -Value "tlsv1,tlsv1.1,sslv3" -Confirm:$false | out-null

    #94485
    Write-host "94485"
    #this is not a real setting on 6.7? 
    #$vmhost | Get-AdvancedSetting -Name UserVars.VMAuthdDisabledProtocols | Set-AdvancedSetting -Value "tlsv1,tlsv1.1,sslv3" -Confirm:$false | out-null

    $cipher = & $plink -v -batch -pw $pswd root@$($h) -hostkey $thumb 'esxcli system settings advanced set -o /UserVars/VMAuthdDisabledProtocols -s "tlsv1,tlsv1.1,sslv3"' 4>$null 3>$null 2>$null

    #94487
    Write-host "94487"
    $sb = & $plink -v -batch -pw $pswd root@$($h) -hostkey $thumb '/usr/lib/vmware/secureboot/bin/secureBoot.py -s' 4>$null 3>$null 2>$null

    if($sb -eq "Disabled"){
        write-host "Secure Boot Check"
        write-host ""
        & $plink -v -batch -pw $pswd root@$($h) -hostkey $thumb '/usr/lib/vmware/secureboot/bin/secureBoot.py -c' 4>$null 3>$null 2>$null
        write-host ""
        Write-Host "Reboot into the bios (IDRAC) and enable secure boot."
    }

    #these are done last because the checks are in a stupid order for bench building and the way we do vlans.
    #94017
    Write-host "94017"
    $vmhost | Get-VMHostService | Where-Object {$_.Label -eq "SSH"} | Set-VMHostService -Policy Off -confirm:$false  | out-null
    #$vmhost | Get-VMHostService | Where {$_.Label -eq "SSH"} | Stop-VMHostService -confirm:$false  | out-null

    #94019
    Write-host "94019"
    $vmhost | Get-VMHostService | Where-Object {$_.Label -eq "ESXi Shell"} | Set-VMHostService -Policy Off -Confirm:$false  | out-null
    #$vmhost | Get-VMHostService | Where {$_.Label -eq "ESXi Shell"} | Stop-VMHostService -Confirm:$false  | out-null

    #94073
    Write-host "94073"
    #do this very last because this will cut coms in the building rack.
    $vmhost | Get-VirtualPortGroup -Name "VM Network" | Set-VirtualPortGroup -VLanId 777 | Out-Null
    #$vmhost | Get-VirtualPortGroup -Name "Management Network" | Set-VirtualPortGroup -VLanId 777 | Out-Null

    Get-Job | Stop-Job
    Get-Job | Remove-Job

    Start-Job -Name "plink_kill" -ScriptBlock {
        Start-Sleep -Seconds 15
        get-process | Where-Object{$_.name -like "plink*"} | Stop-Process -Force -Confirm:$false
    } | out-null

    #idk why esxcli doesnt work here, probably plink escapeing or what ever. esxcfg works tho.
    & $plink -v -batch -pw $pswd root@$($h) -hostkey $thumb "esxcfg-vswitch -p 'Management Network' -v 308 vSwitch0" 4>$null 3>$null 2>$null 1>$null
}
