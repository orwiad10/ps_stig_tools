$server = read-host "Enter computer name of the 2008 server to STIG check"

$ErrorActionPreference = "Silentlycontinue"

invoke-command -ComputerName $server -ScriptBlock {

    if ($PSVersionTable.PSVersion.Major -lt 5){ 
    
        Write-Output "Run the Powershell 2.0 version of the script"
        exit
    } 
    
    $now = Get-Date
    $computer = $env:computername

    #1077
    Write-Output ""
    write-output "V-1077"

    $list = @("Application.evtx", "Security.evtx", "System.evtx")
    $logs = get-childitem -path C:\Windows\System32\winevt\logs\* -include $list

    $table = foreach($l in $logs){
        $a = ($l | get-acl).access
        [pscustomobject]@{
            Log = $l.name
            User = $a.identityreference
            Perm = $a.filesystemrights
        }
    }

    $table | Format-table

    #1112
    Write-Output ""
    write-output "V-1112"

    $adsi = [ADSI]"WinNT://$computer"

    $allaccounts = $adsi.children | where { $_.schemaclassname -eq 'user' } 

    $user = $allaccounts | foreach {

        $user = $_.name
        if($_.lastlogin.date -eq $null -or $_.lastlogin.date -eq ""){
            $LLO = "Never"
        }else{
            $LLO = $_.lastlogin
        }
        $enabled = ($_.properties.userflags.value -band 0x2) -ne 0x2

        [pscustomobject] @{

            name = $user
            lastlogin = $LLO
            enabled = $enabled

        }
    }

    $user | select name, lastlogin, enabled | ft -AutoSize

    #1119
    Write-Output ""
    write-output "V-1119"
    bcdedit /enum | where {$_ -match "description"}

    #1120
    Write-Output ""
    write-output "V-1120 - CAN BE N/A"

    new-item -path $home -name "ftp.txt" -itemtype "file" -value "ls `r`n`quit" | out-null
    ftp -s:$home\ftp.txt localhost | where{$_ -match "Not"}
    remove-item $home\ftp.txt

    #1121
    Write-Output ""
    write-output "V-1121 - CAN BE N/A"
    Write-Output "If V-1120 is anything but 'Not connected'(Not a Finding) Complete this manual check"

    #1122
    Write-Output ""
    Write-Output "V-1122"

    $1 = (get-itemproperty -path 'HKCU:\software\policies\microsoft\Windows\Control Panel\Desktop' -name screensaveactive -ErrorAction SilentlyContinue).screensaveactive
    $2 = (get-itemproperty -path 'HKCU:\software\policies\microsoft\Windows\Control Panel\Desktop' -name screensaverissecure -ErrorAction SilentlyContinue).screensaverissecure
    $3 = (get-itemproperty -path 'HKCU:\software\policies\microsoft\Windows\Control Panel\Desktop' -name screensavetimeout -ErrorAction SilentlyContinue).screensavetimeout
    $4 = $1 + $2 + $3
    if($4 -eq $null){
        $1 = [regex]::match((reg query "HKCU\software\policies\microsoft\Windows\Control Panel\Desktop" /v screensaveactive),"(x(\d+))").value.trim("x")
        $2 = [regex]::match((reg query "HKCU\software\policies\microsoft\Windows\Control Panel\Desktop" /v screensaverissecure),"(x(\d+))").value.trim("x")
        $3 = [regex]::match((reg query "HKCU\software\policies\microsoft\Windows\Control Panel\Desktop" /v screensavetimeout),"(x(\d+))").value.trim("x")
        $4 = $1 + $2 + $3
        if($4 -eq $null){
            Write-Output "No Keys Found"
        }else{
            $1
            $2
            $3
        }
    }else{
        $1
        $2
        $3
    }

    #1127

    Write-Output ""
    Write-Output "V-1127"
    $users = cmd.exe /c "net localgroup administrators" | where {$_ -and $_ -notmatch "command completed successfully"} | select -skip 4
    $out = foreach($u in $users){
        [pscustomobject]@{
            User = $u
        }
    }
    $out | ft -AutoSize



    #1135
    Write-Output ""
    Write-Output "V-1135 - CAN BE N/A"

    $printer = Get-WmiObject win32_printer | where {$_.shared -eq $false}

    if($printer -eq $null){
        Write-Output ""
        Write-Output "No Printers"
    }else{
        Write-Output ""
        Write-Output "Check Control Panel for Access List"
        $printer | select name | ft -AutoSize
    }

    #1168

    Write-Output ""
    Write-Output "V-1168"
    $users2 = cmd.exe /c 'net localgroup "Backup operators"' | where {$_ -and $_ -notmatch "command completed successfully"} | select -skip 4
    if($user2 -eq $null -or $user2 -eq ""){
        Write-Output ""
        Write-Output "No Users in BackUp Group"
    }else{
        $out2 = foreach($u in $users2){
            [pscustomobject]@{
                User = $u
            }
        }
        $out2 | ft -AutoSize
    }

    #3245
    Write-Output ""
    Write-Output "V-3245"

    $folders = Get-WmiObject win32_logicalsharesecuritysetting | where {$_.name -inotlike "*$"}

    if ($folders -eq $null) {
        Write-Output "No shares"
    }else{
        Foreach ($f in $folders){
            if ($folders -eq $null) {
                Write-Output "No shares"
                break
            }

            $find = $f.GetSecurityDescriptor().descriptor.dacl | select @{name="domain";expression={$_.trustee.domain}},@{name="username";expression={$_.trustee.name}},accessmask

            switch ($find.accessmask){

                2032127 {$access = "FullControl"}
                1179785 {$access = "Read"}
                1180063 {$access = "Read,Write"}
                1179817 {$access = "ReadandExecute"}
                1245631 {$access = "ReadandExecute,Modify,Write"}
                1180095 {$access = "ReadandExecute,Write"}
                default {$access = $find.accessmask}
            }

            $user = [pscustomobject] @{
                Name = $f.Name
                Domain = $find.domain
                Username = $find.username
                Permission = $access
            }
            $user | ft -AutoSize
        }
    }

    #3337
    Write-Output ""
    write-output "V-3337"
    secedit /export /cfg $home\secpol.cfg | out-null
    $lsa = Get-Content $home\secpol.cfg | select-string "LSAAnonymousNameLookup"

    if($lsa.Line -contains "0"){
        $lsa.Pattern + "disabled"
    }elseif($lsa.Line -contains "1"){
        $lsa.Pattern + "enabled"
    }else{
        $lsa.line
    }

    #3472
    Write-Output ""
    Write-Output "V-3472"

    $time1 = (get-itemproperty -path 'HKlm:\software\policies\microsoft\W32time\parameters' -name type -ErrorAction SilentlyContinue).type 
    $time2 = (get-itemproperty -path 'HKlm:\software\policies\microsoft\W32time\parameters' -name ntpserver -ErrorAction SilentlyContinue).ntpserver 

    if ($time1 -eq $null){
        $time = [regex]::match((reg query "HKlm\software\policies\microsoft\W32time\parameters" /v type),"(x(\d+))").value.trim("x")
        if ($time1 -eq $null){
            write-output "No type"
        }else{
            $time1
        }
    }else{
        $time1
    }
    if ($time2 -eq $null){
        $time2 = [regex]::match((reg query "HKlm\software\policies\microsoft\W32time\parameters" /v ntpserver),"(x(\d+))").value.trim("x")
        if ($time2 -eq $null){
            Write-Output "No NTPserver"
        }else{
            $time2
        }
    }else{
        $time2
    }

    #3481

    Write-Output ""
    Write-Output "V-3481"

    $wmp = (get-itemproperty -path 'HKcu:\software\policies\microsoft\windowsmediaplayer' -name preventcodecdownload -ErrorAction SilentlyContinue).preventcodecdownload 

    if ($wmp -eq $null){
        $wmp = [regex]::match((reg query "HKcu\software\policies\microsoft\windowsmediaplayer" /v preventcodecdownload),"(x(\d+))").value.trim("x")
        if ($wmp -eq $null){
            write-output "No key found"
        }else{
            $wmp
        }
    }else{
        $wmp
    }

    #3487

    Write-Output ""
    Write-Output "V-3487"

    $services = gwmi win32_service | select -Property displayname, startmode

    $checks = @([pscustomobject]@{Displayname="Application Experience";startmode="Manual"},
    [pscustomobject]@{Displayname="Application Identity";startmode="Manual"},
    [pscustomobject]@{Displayname="Application Information";startmode="Manual"},
    [pscustomobject]@{Displayname="Application Layer Gateway Service";startmode="Manual"},
    [pscustomobject]@{Displayname="Application Management";startmode="Manual"},
    [pscustomobject]@{Displayname="Background Intelligent Transfer Service";startmode="Manual"},
    [pscustomobject]@{Displayname="Base Filtering Engine";startmode="Auto"},
    [pscustomobject]@{Displayname="Certificate Propagation";startmode="Manual"},
    [pscustomobject]@{Displayname="CNG Key Isolation";startmode="Manual  "},
    [pscustomobject]@{Displayname="COM+ Event System";startmode="Auto"},
    [pscustomobject]@{Displayname="COM+ System Application";startmode="Manual"},
    [pscustomobject]@{Displayname="Computer Browser";startmode="Disabled"},
    [pscustomobject]@{Displayname="Credential Manager";startmode="Manual"},
    [pscustomobject]@{Displayname="Cryptographic Services";startmode="Auto"},
    [pscustomobject]@{Displayname="DCOM Server Process Launcher";startmode="Auto"},
    [pscustomobject]@{Displayname="Desktop Window Manager Session Manager";startmode="Auto"},
    [pscustomobject]@{Displayname="DHCP Client";startmode="Auto"},
    [pscustomobject]@{Displayname="Diagnostic Policy Service";startmode="Auto"},
    [pscustomobject]@{Displayname="Diagnostic Service Host";startmode="Manual"},
    [pscustomobject]@{Displayname="Diagnostic System Host";startmode="Manual"},
    [pscustomobject]@{Displayname="Disk Defragmenter";startmode="Manual"},
    [pscustomobject]@{Displayname="Distributed Link Tracking Client";startmode="Auto"},
    [pscustomobject]@{Displayname="Distributed Transaction Coordinator";startmode="Auto"},
    [pscustomobject]@{Displayname="DNS Client";startmode="Auto"},
    [pscustomobject]@{Displayname="Encrypting File System (EFS)";startmode="Manual"},
    [pscustomobject]@{Displayname="Extensible Authentication Protocol";startmode="Manual"},
    [pscustomobject]@{Displayname="Function Discovery Provider Host";startmode="Manual"},
    [pscustomobject]@{Displayname="Function Discovery Resource Publication";startmode="Manual"},
    [pscustomobject]@{Displayname="Group Policy Client";startmode="Auto"},
    [pscustomobject]@{Displayname="Health Key and Certificate Management";startmode="Manual"},
    [pscustomobject]@{Displayname="Human Interface Device Access";startmode="Manual"},
    [pscustomobject]@{Displayname="IKE and AuthIP IPsec Keying Modules";startmode="Manual"},
    [pscustomobject]@{Displayname="Interactive Services Detection";startmode="Manual"},
    [pscustomobject]@{Displayname="Internet Connection Sharing (ICS)";startmode="Disabled"},
    [pscustomobject]@{Displayname="IP Helper";startmode="Auto"},
    [pscustomobject]@{Displayname="IPsec Policy Agent";startmode="Manual"},
    [pscustomobject]@{Displayname="KtmRm for Distributed Transaction Coordinator";startmode="Manual"},
    [pscustomobject]@{Displayname="Link-Layer Topology Discovery Mapper";startmode="Manual"},
    [pscustomobject]@{Displayname="Microsoft .NET Framework NGEN v2.0.50727_X64";startmode="Manual"},
    [pscustomobject]@{Displayname="Microsoft .NET Framework NGEN v2.0.50727_X86";startmode="Manual"},
    [pscustomobject]@{Displayname="Microsoft Fibre Channel Platform Registration Service";startmode="Manual"},
    [pscustomobject]@{Displayname="Microsoft iSCSI Initiator Service";startmode="Manual"},
    [pscustomobject]@{Displayname="Microsoft Software Shadow Copy Provider";startmode="Manual"},
    [pscustomobject]@{Displayname="Multimedia Class Scheduler";startmode="Manual"},
    [pscustomobject]@{Displayname="Netlogon";startmode="Manual"},
    [pscustomobject]@{Displayname="Network Access Protection Agent";startmode="Manual"},
    [pscustomobject]@{Displayname="Network Connections";startmode="Manual"},
    [pscustomobject]@{Displayname="Network List Service";startmode="Manual"},
    [pscustomobject]@{Displayname="Network Location Awareness";startmode="Auto"},
    [pscustomobject]@{Displayname="Network Store Interface Service";startmode="Auto"},
    [pscustomobject]@{Displayname="Performance Counter DLL Host";startmode="Manual"},
    [pscustomobject]@{Displayname="Performance Logs & Alerts";startmode="Manual"},
    [pscustomobject]@{Displayname="Plug and Play";startmode="Auto"},
    [pscustomobject]@{Displayname="PnP-X IP Bus Enumerator";startmode="Disabled"},
    [pscustomobject]@{Displayname="Portable Device Enumerator Service";startmode="Manual"},
    [pscustomobject]@{Displayname="Power";startmode="Auto"},
    [pscustomobject]@{Displayname="Print Spooler";startmode="Auto"},
    [pscustomobject]@{Displayname="Problem Reports and Solutions Control Panel Support";startmode="Manual"},
    [pscustomobject]@{Displayname="Protected Storage";startmode="Manual"},
    [pscustomobject]@{Displayname="Remote Access Auto Connection Manager";startmode="Manual"},
    [pscustomobject]@{Displayname="Remote Access Connection Manager";startmode="Manual"},
    [pscustomobject]@{Displayname="Remote Desktop Configuration";startmode="Manual"},
    [pscustomobject]@{Displayname="Remote Desktop Services";startmode="Manual"},
    [pscustomobject]@{Displayname="Remote Desktop Services UserMode Port Redirector";startmode="Manual"},
    [pscustomobject]@{Displayname="Remote Procedure Call (RPC)";startmode="Auto"},
    [pscustomobject]@{Displayname="Remote Procedure Call (RPC) Locator";startmode="Manual"},
    [pscustomobject]@{Displayname="Remote Registry";startmode="Auto"},
    [pscustomobject]@{Displayname="Resultant Set of Policy Provider";startmode="Manual"},
    [pscustomobject]@{Displayname="Routing and Remote Access";startmode="Disabled"},
    [pscustomobject]@{Displayname="RPC Endpoint Mapper";startmode="Auto"},
    [pscustomobject]@{Displayname="Secondary Logon";startmode="Manual"},
    [pscustomobject]@{Displayname="Secure Socket Tunneling Protocol Service";startmode="Manual"},
    [pscustomobject]@{Displayname="Security Accounts Manager";startmode="Auto"},
    [pscustomobject]@{Displayname="Server";startmode="Auto "},
    [pscustomobject]@{Displayname="Shell Hardware Detection";startmode="Auto"},
    [pscustomobject]@{Displayname="Smart Card";startmode="Manual"},
    [pscustomobject]@{Displayname="Smart Card Removal Policy";startmode="Auto"},
    [pscustomobject]@{Displayname="SNMP Trap";startmode="Manual"},
    [pscustomobject]@{Displayname="Software Protection";startmode="Auto"},
    [pscustomobject]@{Displayname="Special Administration Console Helper";startmode="Manual"},
    [pscustomobject]@{Displayname="SPP Notification Service";startmode="Manual"},
    [pscustomobject]@{Displayname="SSDP Discovery";startmode="Disabled"},
    [pscustomobject]@{Displayname="System Event Notification Service";startmode="Auto"},
    [pscustomobject]@{Displayname="Task Scheduler";startmode="Auto"},
    [pscustomobject]@{Displayname="TCP/IP NetBIOS Helper";startmode="Auto"},
    [pscustomobject]@{Displayname="Telephony";startmode="Manual"},
    [pscustomobject]@{Displayname="Thread Ordering Server";startmode="Manual"},
    [pscustomobject]@{Displayname="TP AutoConnect Service";startmode="Manual"},
    [pscustomobject]@{Displayname="TPM Base Services";startmode="Manual"},
    [pscustomobject]@{Displayname="UPnP Device Host";startmode="Disabled"},
    [pscustomobject]@{Displayname="User Profile Service";startmode="Auto"},
    [pscustomobject]@{Displayname="Virtual Disk";startmode="Manual"},
    [pscustomobject]@{Displayname="Volume Shadow Copy";startmode="Manual"},
    [pscustomobject]@{Displayname="Windows Audio";startmode="Manual"},
    [pscustomobject]@{Displayname="Windows Audio Endpoint Builder";startmode="Manual"},
    [pscustomobject]@{Displayname="Windows Color System";startmode="Manual"},
    [pscustomobject]@{Displayname="Windows Driver Foundation - User-mode Driver Framework";startmode="Manual"},
    [pscustomobject]@{Displayname="Windows Error Reporting Service";startmode="Manual"},
    [pscustomobject]@{Displayname="Windows Event Collector";startmode="Manual"},
    [pscustomobject]@{Displayname="Windows Event Log";startmode="Auto"},
    [pscustomobject]@{Displayname="Windows Firewall";startmode="Auto"},
    [pscustomobject]@{Displayname="Windows Font Cache Service";startmode="Manual"},
    [pscustomobject]@{Displayname="Windows Installer";startmode="Manual"},
    [pscustomobject]@{Displayname="Windows Management Instrumentation";startmode="Auto"},
    [pscustomobject]@{Displayname="Windows Modules Installer";startmode="Manual"},
    [pscustomobject]@{Displayname="Windows Remote Management (WS-Management)";startmode="Auto"},
    [pscustomobject]@{Displayname="Windows Time";startmode="Auto"},
    [pscustomobject]@{Displayname="Windows Update";startmode="Auto"},
    [pscustomobject]@{Displayname="WinHTTP Web Proxy Auto-Discovery Service";startmode="Manual"},
    [pscustomobject]@{Displayname="Wired AutoConfig";startmode="Manual"},
    [pscustomobject]@{Displayname="WMI Performance Adapter";startmode="Manual"},
    [pscustomobject]@{Displayname="Workstation";startmode="Auto"},
    [pscustomobject]@{Displayname="Active Directory Certificate Services";startmode="Auto"},
    [pscustomobject]@{Displayname="Active Directory Domain Services";startmode="Auto"},
    [pscustomobject]@{Displayname="Active Directory Web Services";startmode="Auto"},
    [pscustomobject]@{Displayname="DFS Namespace";startmode="Auto"},
    [pscustomobject]@{Displayname="DFS Replication";startmode="Auto"},
    [pscustomobject]@{Displayname="DNS Server";startmode="Auto"},
    [pscustomobject]@{Displayname="Intersite Messaging";startmode="Auto"},
    [pscustomobject]@{Displayname="Kerberos Key Distribution Center";startmode="Auto"},
    [pscustomobject]@{Displayname="Net.Tcp Port Sharing Service";startmode="Disabled"},
    [pscustomobject]@{Displayname="Windows CardSpace";startmode="Manual"},
    [pscustomobject]@{Displayname="Windows Presentation Foundation Font Cache 3.0.0.0";startmode="Manual"},
    [pscustomobject]@{Displayname="DHCP Server";startmode="Auto"},
    [pscustomobject]@{Displayname="DNS Server";startmode="Auto"},
    [pscustomobject]@{Displayname="Server";startmode="Auto"},
    [pscustomobject]@{Displayname="Workstation";startmode="Auto"},
    [pscustomobject]@{Displayname="Hyper-V Image Management Service";startmode="Auto"},
    [pscustomobject]@{Displayname="Hyper-V Networking Management Service";startmode="Auto"},
    [pscustomobject]@{Displayname="Virtual Machine Management Service";startmode="Auto"},
    [pscustomobject]@{Displayname="Network Policy Server";startmode="Auto"},
    [pscustomobject]@{Displayname="Print Spooler";startmode="Auto"},
    [pscustomobject]@{Displayname="Remote Desktop Configuration";startmode="Manual"},
    [pscustomobject]@{Displayname="Remote Desktop Services";startmode="Auto"},
    [pscustomobject]@{Displayname="Remote Desktop Services UserMode Port";startmode="Manual"},
    [pscustomobject]@{Displayname="Application Host Helper Service";startmode="Auto"},
    [pscustomobject]@{Displayname="Windows Process Activation";startmode="Manual"},
    [pscustomobject]@{Displayname="World Wide Web Publishing Service";startmode="Auto"})

    Write-Output "Services NOT in Check or DIFFERENT"

    $services = compare-object $checks $services -Property displayname, startmode | where {$_.sideindicator -eq "=>"}

    $services | where {$_.startmode -ne "Disabled"} | ft -AutoSize

    #3828

    Write-Output ""
    Write-Output "V-3828 - CAN BE N/A"

    Write-Output "Is Server Up to Date in ACAS?"
    
    #6840 and 7002

    Write-Output ""
    Write-Output "V-6840 and V-7002"
    Write-Output ""
    Write-Output "Look for flags 'Dont_Expire_Passwords' and 'PASSWD_NOTREQD'" 

    $adsi = [ADSI]"WinNT://$computer"

    $allaccounts = $adsi.children | where { $_.schemaclassname -eq 'user' }

        Function Convert-UserFlag  {

            Param ($UserFlag)

            $List = New-Object System.Collections.ArrayList
        
            Switch ($UserFlag){

            ($UserFlag -BOR 0x0001) {[void]$List.Add('SCRIPT')}
            ($UserFlag -BOR 0x0002) {[void]$List.Add('ACCOUNTDISABLE')}
            ($UserFlag -BOR 0x0008) {[void]$List.Add('HOMEDIR_REQUIRED')}
            ($UserFlag -BOR 0x0010) {[void]$List.Add('LOCKOUT')}
            ($UserFlag -BOR 0x0020) {[void]$List.Add('PASSWD_NOTREQD')}
            ($UserFlag -BOR 0x0040) {[void]$List.Add('PASSWD_CANT_CHANGE')}
            ($UserFlag -BOR 0x0080) {[void]$List.Add('ENCRYPTED_TEXT_PWD_ALLOWED')}
            ($UserFlag -BOR 0x0100) {[void]$List.Add('TEMP_DUPLICATE_ACCOUNT')}
            ($UserFlag -BOR 0x0200) {[void]$List.Add('NORMAL_ACCOUNT')}
            ($UserFlag -BOR 0x0800) {[void]$List.Add('INTERDOMAIN_TRUST_ACCOUNT')}
            ($UserFlag -BOR 0x1000) {[void]$List.Add('WORKSTATION_TRUST_ACCOUNT')}
            ($UserFlag -BOR 0x2000) {[void]$List.Add('SERVER_TRUST_ACCOUNT')}
            ($UserFlag -BOR 0x10000) {[void]$List.Add('DONT_EXPIRE_PASSWORD')}
            ($UserFlag -BOR 0x20000) {[void]$List.Add('MNS_LOGON_ACCOUNT')}
            ($UserFlag -BOR 0x40000) {[void]$List.Add('SMARTCARD_REQUIRED')}
            ($UserFlag -BOR 0x80000) {[void]$List.Add('TRUSTED_FOR_DELEGATION')}
            ($UserFlag -BOR 0x100000) {[void]$List.Add('NOT_DELEGATED')}
            ($UserFlag -BOR 0x200000) {[void]$List.Add('USE_DES_KEY_ONLY')}
            ($UserFlag -BOR 0x400000) {[void]$List.Add('DONT_REQ_PREAUTH')}
            ($UserFlag -BOR 0x800000) {[void]$List.Add('PASSWORD_EXPIRED')}
            ($UserFlag -BOR 0x1000000) {[void]$List.Add('TRUSTED_TO_AUTH_FOR_DELEGATION')}
            ($UserFlag -BOR 0x04000000) {[void]$List.Add('PARTIAL_SECRETS_ACCOUNT')}

            }

            $List -join ', '

    } 

    $users = foreach ($a in $allaccounts){

        $UserFlag = $a.UserFlags.value
    
        [pscustomobject]@{
            Name = $a.Name
            Flags = Convert-UserFlag -UserFlag $Userflag
        }
    }

    $users | select name, flags | ft -AutoSize

    #14268

    Write-Output ""
    Write-Output "V-14268"

    $zone = (get-itemproperty -path 'HKcu:\software\microsoft\windows\currentversion\policies\attachments' -name savezoneinformation -ErrorAction SilentlyContinue).savezoneinformation 

    if ($zone -eq $null){
        $zone = [regex]::match((reg query "HKcu\software\microsoft\windows\currentversion\policies\attachments" /v savezoneinformation),"(x(\d+))").value.trim("x")
        if ($zone -eq $null){
            write-output "No key found"
        }else{
            $zone
        }
    }else{
        $zone
    }

    #14269

    Write-Output ""
    Write-Output "V-14269"

    $zone1 = (get-itemproperty -path 'HKcu:\software\microsoft\windows\currentversion\policies\attachments' -name hidezoneinfoonproperties -ErrorAction SilentlyContinue).hidezoneinfoonproperties

    if ($zone1 -eq $null){
        $zone1 = [regex]::match((reg query "HKcu\software\microsoft\windows\currentversion\policies\attachments" /v hidezoneinfoonproperties),"(x(\d+))").value.trim("x")
        if ($zone1 -eq $null){
            write-output "No key found"
        }else{
            $zone1
        }
    }else{
        $zone1
    }

    #14270

    Write-Output ""
    Write-Output "V-14270"

    $zone2 = (get-itemproperty -path 'HKcu:\software\microsoft\windows\currentversion\policies\attachments' -name scanwithantivirus -ErrorAction SilentlyContinue).scanwithantivirus

    if ($zone2 -eq $null){
        $zone2 = [regex]::match((reg query "HKcu:\software\microsoft\windows\currentversion\policies\attachments" /v scanwithantivirus),"(x(\d+))").value.trim("x")
        if ($zone2 -eq $null){
            write-output "No key found"
        }else{
            $zone2
        }
    }else{
        $zone2
    }

    #14271

    Write-Output ""
    Write-Output "V-14271 - CAN BE N/A"

    $pass = $allaccounts | ForEach-Object {

        $pwage = $_.passwordage.value
        $pwlastset = $now.AddSeconds(-$pwage)

        [pscustomobject]@{
            Name = $_.name
            PasswordLastSet = $pwlastset
        }
    }

    $pass | ft -AutoSize

    #15727

    Write-Output ""
    Write-Output "V-15727"

    $share = (get-itemproperty -path 'HKcu:\software\microsoft\windows\currentversion\policies\explorer' -name noinplacesharing -ErrorAction SilentlyContinue).noinplacesharing

    if ($share -eq $null){
        $share = [regex]::match((reg query "HKcu\software\microsoft\windows\currentversion\policies\explorer" /v noinplacesharing),"(x(\d+))").value.trim("x")
        if ($share -eq $null){
            write-output "No key found"
        }else{
            $share
        }
    }else{
        $share
    }

    #16021

    Write-Output ""
    Write-Output "V-16021"

    $assis = (get-itemproperty -path 'HKcu:\software\policies\microsoft\assistance\client\1.0' -name noimplicitfeedback -ErrorAction SilentlyContinue).noimplicitfeedback

    if ($assis -eq $null){
        $assis = [regex]::match((reg query "HKcu\software\policies\microsoft\assistance\client\1.0" /v noimplicitfeedback),"(x(\d+))").value.trim("x")
        if ($assis -eq $null){
            write-output "No key found"
        }else{
            $assis
        }
    }else{
        $assis
    }

    #16048

    Write-Output ""
    Write-Output "V-16048"

    $assis1 = (get-itemproperty -path 'HKcu:\software\policies\microsoft\assistance\client\1.0' -name noexplicitfeedback -ErrorAction SilentlyContinue).noexplicitfeedback

    if ($assis1 -eq $null){
        $assis1 = [regex]::match((reg query "HKcu\software\policies\microsoft\assistance\client\1.0" /v noexplicitfeedback),"(x(\d+))").value.trim("x")
        if ($assis1 -eq $null){
            write-output "No key found"
        }else{
            $assis1
        }
    }else{
        $assis1
    }

    #26469
    Write-Output ""
    write-output "V-26469"
    $credman = Get-Content $home\secpol.cfg | select-string "SeTrustedCredManAccessPrivilege"
    if($credman -eq $null){
        Write-Output "No Setting Found"
    }else{
        $match = ([regex]::matches($credman,"(S(-\d+){2,8})")).value
        if($match -ne $null){
            foreach($m in $match){
                $usr = get-aduser -filter {sid -eq $m}
                if($usr -ne $null){
                    $usr
                }else{
                    $m
                }
            }
        } 
    }

    #72753

    Write-Output ""
    Write-Output "V-72753"

    $credcheck = (get-itemproperty -path 'HKlm:\system\currentcontrolset\control\securityproviders\wdigest' -name uselogoncredential -ErrorAction SilentlyContinue).uselogoncredential

    if ($credcheck -eq $null){
        $credcheck  = [regex]::match((reg query "HKlm\system\currentcontrolset\control\securityproviders\wdigest" /v uselogoncredential),"(x(\d+))").value.trim("x")
        if ($credcheck -eq $null){
            write-output "No key found"
        }else{
            $credcheck
        }
    }else{
        $credcheck
    }

    #75915
    Write-Output ""
    write-output "V-75915"
    $matches = ([regex]::matches($lsa,"(S(-\d+){2,8})")).value
    Write-Output "Unresolved SID's below, please remove them."
    foreach($m in $matches | where{$_.length -gt "12" -and $_ -notlike "*-512" -and $_ -notlike "*-519"} | select -Unique){
        if((get-aduser -filter {sid -eq $m}) -eq $null){
            $m
        }
    }
    remove-item $home\secpol.cfg
}