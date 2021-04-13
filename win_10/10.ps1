#V2R1
param($credential)

function stig_object {
    param($vulnid,
        [ValidateSet('Open','NotAFinding','Not_Applicable')]
        $status,
        $data
    )

    [pscustomobject]@{
        VulnID = $vulnid
        Status = $status
        Data   = $data
    }
}

Function Convert-UserFlag {
    Param ($UserFlag)

    $List = New-Object System.Collections.ArrayList

    Switch($UserFlag){
        ($UserFlag -BOR 0x0001)     {[void]$List.Add('SCRIPT')}
        ($UserFlag -BOR 0x0002)     {[void]$List.Add('ACCOUNTDISABLE')}
        ($UserFlag -BOR 0x0008)     {[void]$List.Add('HOMEDIR_REQUIRED')}
        ($UserFlag -BOR 0x0010)     {[void]$List.Add('LOCKOUT')}
        ($UserFlag -BOR 0x0020)     {[void]$List.Add('PASSWD_NOTREQD')}
        ($UserFlag -BOR 0x0040)     {[void]$List.Add('PASSWD_CANT_CHANGE')}
        ($UserFlag -BOR 0x0080)     {[void]$List.Add('ENCRYPTED_TEXT_PWD_ALLOWED')}
        ($UserFlag -BOR 0x0100)     {[void]$List.Add('TEMP_DUPLICATE_ACCOUNT')}
        ($UserFlag -BOR 0x0200)     {[void]$List.Add('NORMAL_ACCOUNT')}
        ($UserFlag -BOR 0x0800)     {[void]$List.Add('INTERDOMAIN_TRUST_ACCOUNT')}
        ($UserFlag -BOR 0x1000)     {[void]$List.Add('WORKSTATION_TRUST_ACCOUNT')}
        ($UserFlag -BOR 0x2000)     {[void]$List.Add('SERVER_TRUST_ACCOUNT')}
        ($UserFlag -BOR 0x10000)    {[void]$List.Add('DONT_EXPIRE_PASSWORD')}
        ($UserFlag -BOR 0x20000)    {[void]$List.Add('MNS_LOGON_ACCOUNT')}
        ($UserFlag -BOR 0x40000)    {[void]$List.Add('SMARTCARD_REQUIRED')}
        ($UserFlag -BOR 0x80000)    {[void]$List.Add('TRUSTED_FOR_DELEGATION')}
        ($UserFlag -BOR 0x100000)   {[void]$List.Add('NOT_DELEGATED')}
        ($UserFlag -BOR 0x200000)   {[void]$List.Add('USE_DES_KEY_ONLY')}
        ($UserFlag -BOR 0x400000)   {[void]$List.Add('DONT_REQ_PREAUTH')}
        ($UserFlag -BOR 0x800000)   {[void]$List.Add('PASSWORD_EXPIRED')}
        ($UserFlag -BOR 0x1000000)  {[void]$List.Add('TRUSTED_TO_AUTH_FOR_DELEGATION')}
        ($UserFlag -BOR 0x04000000) {[void]$List.Add('PARTIAL_SECRETS_ACCOUNT')}
    }

    $List -join ', '
}

$buildnum = (get-itemproperty -path 'HKlm:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -name ReleaseId -ErrorAction SilentlyContinue).ReleaseId

secedit /export /cfg "$home\desktop\conf.inf" | out-null
$sec = Get-Content "$home\desktop\conf.inf"

New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
$sids = ((Get-ChildItem 'HKU:\').name | Select-String -Pattern 'S-\d-(?:\d+-){4,14}\d+').Matches.Value      

#220698
$tpm = (Get-Tpm).tpmready
if($tpm -eq $false){
    stig_object -vulnid "V-220698" -status Open -data $tpm
}else{
    stig_object -vulnid "V-220698" -status NotAFinding -data $tpm
}

#220699
$bl = (Get-BitLockerVolume).volumestatus

if($bl -eq "FullyEncrypted"){
    stig_object -vulnid "V-220699" -status NotAFinding -data $bl
}else{
    stig_object -vulnid "V-220699" -status NotAFinding -data $bl
}

#220700	
$secboot = (Get-SecureBootUEFI -Name SecureBoot).bytes

if($secboot -eq 1){
    stig_object -vulnid "V-220700" -status NotAFinding -data $secboot
}else{
    stig_object -vulnid "V-220700" -status Open -data $secboot
}

#220701
$HKLM        = 2147483650
$sSubKeyName = "Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall", "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
$wmi         = [wmiclass]"\\$env:computername\ROOT\DEFAULT:StdRegProv"

$installed = foreach($s in $sSubKeyName){ 
    foreach($r in ($wmi.Enumkey($HKLM, $s)).snames){
        $newsub = "$s" + "\$r"

        [pscustomobject]@{
            DisplayName = $wmi.getstringvalue($HKLM, $newsub, "DisplayName").svalue
            Publisher   = $wmi.getstringvalue($HKLM, $newsub, "Publisher").svalue
        }
    }
}

$macfound = ($installed | where{$_.publisher -like "*mcafee*"}).displayname | select -Unique

if($macfound){
    stig_object -vulnid "V-220701" -status NotAFinding -data $macfound
}else{
    stig_object -vulnid "V-220701" -status Open -data "No Mcafee found"
}

#220703
$bitlockreg1 = (get-itemproperty -path 'HKlm:\SOFTWARE\Policies\Microsoft\fve\' -name UseTPMPIN -ErrorAction SilentlyContinue).UseTPMPIN
$bitlockreg2 = (get-itemproperty -path 'HKlm:\SOFTWARE\Policies\Microsoft\fve\' -name UseTPMKeyPIN -ErrorAction SilentlyContinue).UseTPMKeyPIN

$bitadd      = [int]$bitlockreg1 + [int]$bitlockreg1

if($bitadd -ge 1){
    stig_object -vulnid "V-220703" -status NotAFinding -data $bitadd
}else{
    stig_object -vulnid "V-220703" -status Open -data $bitadd
}

#220704
$bitlockreg3 = [int](get-itemproperty -path 'HKlm:\SOFTWARE\Policies\Microsoft\fve\' -name MinimumPIN -ErrorAction SilentlyContinue).MinimumPIN

if($bitlockreg3 -ge 6){
    stig_object -vulnid "V-220704" -status NotAFinding -data $bitlockreg3
}else{
    stig_object -vulnid "V-220704" -status Open -data $bitlockreg3
}

#220705
$applock = (Get-AppLockerPolicy -Effective).version

if($pplock -eq 1){
    stig_object -vulnid "V-220705" -status NotAFinding -data $applock
}else{
    stig_object -vulnid "V-220705" -status Open -data $applock
}

#220707
$macv = $macfound | where{$_ -like "McAfee Virus*"}

if($macv){
    stig_object -vulnid "V-220707" -status NotAFinding -data $macv
}else{
    stig_object -vulnid "V-220707" -status Open -data "No Mcafee found"
}

#220709
$cxOptions                  = new-object System.Management.ConnectionOptions
$cxOptions.Impersonation    = [System.Management.ImpersonationLevel]::Impersonate
$cxOptions.EnablePrivileges = $true

$mgmtScope   = new-object System.Management.ManagementScope -ArgumentList "root\WMI",$cxOptions
$mgmtPath    = new-object System.Management.ManagementPath -ArgumentList 'root\WMI:BcdObject.Id="{9dea862c-5cdd-4e70-acc1-f32b344d4795}",StoreFilePath=""'
$mgmtObject  = new-object System.Management.ManagementObject -ArgumentList $mgmtScope,$mgmtPath,$null
$objBCD      = $mgmtObject.GetElement(0x24000001)
$objElements = $objBCD.GetPropertyValue("Element")
$strOldID    = "{9dea862c-5cdd-4e70-acc1-f32b344d4795}"

$220709data = $(for($i = 0; $i -lt $objElements.Ids.Count; $i++) {
    $mgmtPath.Path = $mgmtPath.Path.Replace($strOldID,$objElements.Ids[$i])
    $strOldID      = $objElements.Ids[$i]
    $objBCDId      = new-object System.Management.ManagementObject -ArgumentList $mgmtScope,$mgmtPath,$null
    $strOS         = $objBCDId.GetElement(0x12000004)
    $strOS.Element.String
})

if($220709data.count -eq 1 -and ((Get-WmiObject -Class Win32_OperatingSystem).Caption) -like "*$220709data*"){

    stig_object -vulnid "V-220709" -status NotAFinding -data $220709data
}else{
    
    stig_object -vulnid "V-220709" -status Open -data $220709data
}

#220710
$folders = Get-WmiObject win32_logicalsharesecuritysetting | where {$_.name -inotlike "*$"}

if($folders -eq $null) {
    stig_object -vulnid "V-220710" -status NotAFinding -data "No shares"
}else{
    $perm = Foreach ($f in $folders){
        if ($folders -eq $null) {
            stig_object -vulnid "V-220710" -status NotAFinding -data "No shares"
            break
        }

        $find = $f.GetSecurityDescriptor().descriptor.dacl | select @{name="domain";expression={$_.trustee.domain}},@{name="username";expression={$_.trustee.name}}, accessmask

        switch ($find.accessmask){

            2032127 {$access = "FullControl"}
            1179785 {$access = "Read"}
            1180063 {$access = "Read,Write"}
            1179817 {$access = "ReadandExecute"}
            1245631 {$access = "ReadandExecute,Modify,Write"}
            1180095 {$access = "ReadandExecute,Write"}
            default {$access = $find.accessmask}
        }

        [pscustomobject] @{
            Name = $f.Name
            Domain = $find.domain
            Username = $find.username
            Permission = $access
        }
    }

    stig_object -vulnid "V-220710" -status Open -data ($perm | select name, domain, username, permission)
}

#220711
$adsi        = [ADSI]"WinNT://$env:computername"
$allaccounts = $adsi.children | where {$_.schemaclassname -eq 'user'} 
$user        = $allaccounts | foreach {

    if($_.lastlogin.date -eq $null -or $_.lastlogin.date -eq ""){
        $LLO = "Never"
    }else{
        $LLO = $_.lastlogin
    }
    $enabled = ($_.properties.userflags.value -band 0x2) -ne 0x2

    [pscustomobject] @{
        name      = $_.name
        lastlogin = $LLO.tostring()
        enabled   = $enabled
    }
}

$foundusers = ($user | select name, lastlogin, enabled)

stig_object -vulnid "V-220711" -status Open -data $foundusers

#220712
$users = cmd.exe /c "net localgroup administrators" 4>$null 3>$null 2>$null | where {$_ -and $_ -notmatch "command completed successfully"} | select -skip 4 
$out = foreach($u in $users){
    [pscustomobject]@{
        User = $u
    }
}

stig_object -vulnid "V-220712" -status Open -data $out

#220713
$users2 = cmd.exe /c 'net localgroup "Backup operators"' 4>$null 3>$null 2>$null | where {$_ -and $_ -notmatch "command completed successfully"} | select -skip 4

if($user2 -eq $null -or $user2 -eq ""){
    
    stig_object -vulnid "V-220713" -status NotAFinding -data "No Users in BackUp Group"
}else{
    
    $out2 = foreach($u in $users2){
        [pscustomobject]@{
            User = $u
        }
    }

    stig_object -vulnid "V-220713" -status Open -data $out2
}

#220714
$users3 = cmd.exe /c 'net localgroup "Hyper-V Administrators"' 4>$null 3>$null 2>$null | where {$_ -and $_ -notmatch "command completed successfully"} | select -skip 4

if($user3 -eq $null -or $user3 -eq ""){

    stig_object -vulnid "V-220714" -status NotAFinding -data "No Users in Hyper-V Administrators Group"
}else{
    
    $out3 = foreach($u in $users3){
        [pscustomobject]@{
            User = $u
        }
    }

    stig_object -vulnid "V-220714" -status NotAFinding -data $out3
}

#220715
$adsi = [ADSI]"WinNT://$env:computername"
$allaccounts = $adsi.children | where { $_.schemaclassname -eq 'user' }

$adsiusers = foreach ($a in $allaccounts){
    $UserFlag = $a.UserFlags.value

    [pscustomobject]@{
        Name = $a.Name
        Flags = Convert-UserFlag -UserFlag $Userflag
    }
}

stig_object -vulnid "V-220715" -status Open -data ($adsiusers | select name, flags)

#220717
[string[]]$icaclsc = "c:\","c:\program files","c:\windows" | %{icacls $_ | select -SkipLast 1}

stig_object -vulnid "V-220717" -status Open -data $icaclsc

#220723
$drives = (Get-Volume | where{$_.DriveLetter -ne $null}).driveletter

$allfiles = foreach($d in $drives){
    & cmd.exe /c "dir $($d):\ /A-D /b /s" 4>$null 3>$null 2>$null
}

$certs = $allfiles | where{$_ -like "*pfx" -or $_ -like "*p12"}

if($certs){
    stig_object -vulnid "V-220723" -status Open -data $certs
}else{
    stig_object -vulnid "V-220723" -status NotAFinding -data "No certs found"
}

#220724
$macfire = $macfound | where{$_ -like "McAfee Host*"}

if($macfire){
    stig_object -vulnid "V-220724" -status NotAFinding -data $macfire
}else{
    stig_object -vulnid "V-220724" -status Open -data "No Firewall Found"
}

#V-220725
#someday

#220733
$matches = ([regex]::matches($sec,"(S(-\d+){2,8})")).value

$ghostsids = $(foreach($m in $matches | where{$_.length -gt "12" -and $_ -notlike "*-512" -and $_ -notlike "*-519"} | select -Unique){
    
    $objSID  = New-Object System.Security.Principal.SecurityIdentifier ("$m")
    $objUser = ($objSID.Translate( [System.Security.Principal.NTAccount])).value
    
    if(!$objUser){
        ($sec | select-string $m) | %{$_.ToString().Split(" = ")[0]} | %{
            [pscustomobject]@{
                right = $_
                sid = $m
            }
        }
    }
})

if($ghostsids -eq $null){
    stig_object -vulnid "V-220733" -status NotAFinding -data "No SIDs Found"
}else{
    stig_object -vulnid "V-220733" -status Open -data $ghostsids
}

#220734
$bluetooth = Get-WmiObject Win32_PnPEntity | Where{$_.ConfigManagerErrorCode -eq 0 -and $_.caption -like "*bluetooth*"} | select caption

if(!$blutooth){
    stig_object -vulnid "V-220734" -status Not_Applicable -data "No Bluetooth Found"
}else{
    stig_object -vulnid "V-220734" -status Open -data $bluetooth
}

#220735
if(!$blutooth){
    stig_object -vulnid "V-220735" -status Not_Applicable -data "No Bluetooth Found"
}else{
    stig_object -vulnid "V-220735" -status Open -data $bluetooth
}

#220736
if(!$blutooth){
    stig_object -vulnid "V-220736" -status Not_Applicable -data "No Bluetooth Found"
}else{
    stig_object -vulnid "V-220736" -status Open -data $bluetooth
}

#220737
Get-Process | where{$_.name -eq "iexplore"} | Stop-Process -Force | out-null

try{
    Start-Process -FilePath 'C:\Program Files\Internet Explorer\iexplore.exe' -ErrorVariable ieerror -ErrorAction Stop -Credential $credential -NoNewWindow | out-null
    Get-Process | where{$_.name -eq "iexplore"} | Stop-Process -Force | out-null

    stig_object -vulnid "V-220737" -status Open -data "IE Opened as $($credential.username)"
}catch{
    
    stig_object -vulnid "V-220737" -status NotAFinding -data $ieerror.message
}

$auditpol = auditpol /get /category:*

#220753
stig_object -vulnid "V-220753" -status Open -data ($auditpol  | %{if($_ -like "*Plug and Play Events*Success"){$_}})

#220756
stig_object -vulnid "V-220756" -status Open -data ($auditpol  | %{if($_ -like "*Group Membership*"){$_}})

#220765
stig_object -vulnid "V-220765" -status Open -data ($auditpol  | %{if($_ -like "*Removable Storage*"){$_}})

#220766
stig_object -vulnid "V-220766" -status Open -data ($auditpol  | %{if($_ -like "*Removable Storage*"){$_}})

#220792
$lockscreen = (get-itemproperty -path 'HKlm:\SOFTWARE\Policies\Microsoft\Windows\Personalization\' -name NoLockScreenCamera -ErrorAction SilentlyContinue).NoLockScreenCamera

if($lockscreen -eq 1){
   stig_object -vulnid "V-220792" -status NotAFinding -data $lockscreen
}else{
    if($lockscreen -eq $null){
        stig_object -vulnid "V-220792" -status Open -data "No key found"
    }else{
        stig_object -vulnid "V-220792" -status Open -data "No key found"
    }
}

#220793
#someday

#220805
$ecc = (get-itemproperty -path 'HKlm:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002\' -name EccCurves -ErrorAction SilentlyContinue).EccCurves

if($ecc.Contains("NistP384") -and $ecc.contains("NistP256")){
    stig_object -vulnid "V-220805" -status NotAFinding -data $ecc
}else{
    stig_object -vulnid "V-220805" -status Open -data $ecc
}

$devguard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | select RequiredSecurityProperties, VirtualizationBasedSecurityStatus, SecurityServicesRunning

#220811
stig_object -vulnid "V-220811" -status Open -data $devguard

#220812
stig_object -vulnid "V-220812" -status Open -data $devguard

#220846
$psp = (get-itemproperty -path 'HKlm:\SOFTWARE\Policies\Microsoft\PassportForWork\' -name RequireSecurityDevice -ErrorAction SilentlyContinue).RequireSecurityDevice

if($psp -eq 1){
    stig_object -vulnid "V-220846" -status NotAFinding -data $psp
}else{
    if($psp -eq $null){
        stig_object -vulnid "V-220846" -status Open -data "No key found"
    }else{
        stig_object -vulnid "V-220846" -status Open -data $psp
    }
}

#220861
#someday

#220869
$ap1 = (get-itemproperty -path 'HKlm:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy\' -name LetAppsActivateWithVoice -ErrorAction SilentlyContinue).LetAppsActivateWithVoice
$ap2 = (get-itemproperty -path 'HKlm:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy\' -name LetAppsActivateWithVoiceAboveLock -ErrorAction SilentlyContinue).LetAppsActivateWithVoiceAboveLock

if($ap1 -eq 2){
    stig_object -vulnid "V-220869" -status Not_Applicable -data $ap
}else{
    if($ap2 -eq 2){
        stig_object -vulnid "V-220869" -status NotAFinding -data $ap
    }else{
        if($ap2 -eq $null){
            stig_object -vulnid "V-220869" -status Open -data "No key found"
        }elseif($ap2 -ne 2){
            stig_object -vulnid "V-220869" -status Open -data $ap
        }
    }
}

#220872
#someday

$buildnum = ([regex]::Matches((Reg Query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v ReleaseId),"\d{4}")).value

#220873
if($buildnum -le 1607){
    stig_object -vulnid "V-220873" -status Not_Applicable -data $buildnum
}else{
    #todo
}

#220874
if($buildnum -le 1607){
    stig_object -vulnid "V-220874" -status Not_Applicable -data $buildnum
}else{
    #todo
}

#220875
if($buildnum -le 1607){
    stig_object -vulnid "V-220875" -status Not_Applicable -data $buildnum
}else{
    #todo
}

#220876
if($buildnum -le 1607){
    stig_object -vulnid "V-220876" -status Not_Applicable -data $buildnum
}else{
    #todo
}

#220877
if($buildnum -le 1607){
    stig_object -vulnid "V-220877" -status Not_Applicable -data $buildnum
}else{
    #todo
}

#220878
if($buildnum -le 1607){
    stig_object -vulnid "V-220878" -status Not_Applicable -data $buildnum
}else{
    #todo
}

#220879
if($buildnum -le 1607){
    stig_object -vulnid "V-220879" -status Not_Applicable -data $buildnum
}else{
    #todo
}

#220880
if($buildnum -le 1607){
    stig_object -vulnid "V-220880" -status Not_Applicable -data $buildnum
}else{
    #todo
}

#220881
if($buildnum -le 1607){
    stig_object -vulnid "V-220881" -status Not_Applicable -data $buildnum
}else{
    #todo
}

#220882
if($buildnum -le 1607){
    stig_object -vulnid "V-220882" -status Not_Applicable -data $buildnum
}else{
    #todo
}

#220883
if($buildnum -le 1607){
    stig_object -vulnid "V-220883" -status Not_Applicable -data $buildnum
}else{
    #todo
}

#220884
if($buildnum -le 1607){
    stig_object -vulnid "V-220884" -status Not_Applicable -data $buildnum
}else{
    #todo
}

#220885
if($buildnum -le 1607){
    stig_object -vulnid "V-220885" -status Not_Applicable -data $buildnum
}else{
    #todo
}

#220886
if($buildnum -le 1607){
    stig_object -vulnid "V-220886" -status Not_Applicable -data $buildnum
}else{
    #todo
}

#220887
if($buildnum -le 1607){
    stig_object -vulnid "V-220887" -status Not_Applicable -data $buildnum
}else{
    #todo
}

#220888
if($buildnum -le 1607){
    stig_object -vulnid "V-220888" -status Not_Applicable -data $buildnum
}else{
    #todo
}

#220889
if($buildnum -le 1607){
    stig_object -vulnid "V-220889" -status Not_Applicable -data $buildnum
}else{
    #todo
}

#220890
if($buildnum -le 1607){
    stig_object -vulnid "V-220890" -status Not_Applicable -data $buildnum
}else{
    #todo
}

#220891
if($buildnum -le 1607){
    stig_object -vulnid "V-220891" -status Not_Applicable -data $buildnum
}else{
    #todo
}

#220892
if($buildnum -le 1607){
    stig_object -vulnid "V-220892" -status Not_Applicable -data $buildnum
}else{
    #todo
}

#220893
if($buildnum -le 1607){
    stig_object -vulnid "V-220893" -status Not_Applicable -data $buildnum
}else{
    #todo
}

#220894
if($buildnum -le 1607){
    stig_object -vulnid "V-220894" -status Not_Applicable -data $buildnum
}else{
    #todo
}

#220895
if($buildnum -le 1607){
    stig_object -vulnid "V-220895" -status Not_Applicable -data $buildnum
}else{
    #todo
}

#220896
if($buildnum -le 1607){
    stig_object -vulnid "V-220896" -status Not_Applicable -data $buildnum
}else{
    #todo
}

#220897
if($buildnum -le 1607){
    stig_object -vulnid "V-220897" -status Not_Applicable -data $buildnum
}else{
    #todo
}

#220898
if($buildnum -le 1607){
    stig_object -vulnid "V-220898" -status Not_Applicable -data $buildnum
}else{
    #todo
}

#220899
if($buildnum -le 1607){
    stig_object -vulnid "V-220899" -status Not_Applicable -data $buildnum
}else{
    #todo
}

#220900
if($buildnum -le 1607){
    stig_object -vulnid "V-220900" -status Not_Applicable -data $buildnum
}else{
    #todo
}

#220901
if($buildnum -le 1607){
    stig_object -vulnid "V-220901" -status Not_Applicable -data $buildnum
}else{
    #todo
}

#220907
$rootKey = [Microsoft.Win32.Registry]::LocalMachine

$regkeys = "SECURITY","SOFTWARE","SYSTEM"

$regperms = $(foreach($r in $regkeys){

    $key = $rootKey.OpenSubKey($r, 'ReadWriteSubTree', 'ReadPermissions')

    [pscustomobject]@{
        Key         = $r
        Permissions = $key.GetAccessControl().access | select IdentityReference, RegistryRights, AccessControlType, IsInherited
    }
})

stig_object -vulnid "V-220907" -status Open -data $regperms

#220921
#someday

#220922
#someday

#220928
$lsa = (($sec | select-string "LSAAnonymousNameLookup").Line -split " = ")[1]

if($lsa -eq 0){
    stig_object -vulnid "V-220928" -status NotAFinding -data $lsa
}else{
    if($lsa -eq $null){
        stig_object -vulnid "V-220928" -status Open -data "No Data Found"
    }else{
        stig_object -vulnid "V-220928" -status Open -data $lsa
    }
}

#220946
#someday

#220952
stig_object -vulnid "V-220952" -status Open -data (Get-LocalUser –Name * | Select-Object name, passwordlastset)

#220954
$to = $null

foreach($s in $sids){

    $to = (get-itemproperty -path "HKu:\$s\software\policies\microsoft\windows\currentversion\pushnotifications\" -name NoToastApplicationNotificationOnLockscreen -ErrorAction SilentlyContinue).NoToastApplicationNotificationOnLockscreen

    if($to -eq 1){
        stig_object -vulnid "V-220954" -status NotAFinding -data $to

        $tofound = 1

        break
    }
}

if($to -eq $null){
    stig_object -vulnid "V-220954" -status Open -data "No key found"
}elseif($to -ne 1){
    stig_object -vulnid "V-220954" -status Open -data $to
}

#220955
$zone = $null

foreach($s in $sids){

    $zone = (get-itemproperty -path "HKu:\$s\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments\" -name SaveZoneInformation -ErrorAction SilentlyContinue).SaveZoneInformation

    if($zone -eq 1){
        stig_object -vulnid "V-220955" -status NotAFinding -data $zone

        break
    }
}

if($zone -eq $null){
    stig_object -vulnid "V-220955" -status Open -data "No key found"
}elseif($zone -ne 1){
    stig_object -vulnid "V-220955" -status Open -data $zone
}

#63587
$dodcerts = Get-ChildItem -Path Cert:Localmachine\disallowed | Where {$_.Issuer -Like "*DoD Interoperability*" -and $_.Subject -Like "*DoD*"} | select Subject, Issuer, Thumbprint, NotAfter

stig_object -vulnid "V-63587" -status Open -data $dodcerts 

#77083
$d = Confirm-SecureBootUEFI -ErrorVariable ProcessError

if($ProcessError -eq $true){
    stig_object -vulnid "V-76505" -status Open -data "Legacy"
}else{
    stig_object -vulnid "V-76505" -status NotAFinding -data "UEFI"
}

#82137
$oned = $null

foreach($s in $sids){

    $oned = (get-itemproperty -path "HKu:\$s\Software\Policies\Microsoft\OneDrive\" -name DisablePersonalSync -ErrorAction SilentlyContinue).DisablePersonalSync

    if($oned -eq 1){
        stig_object -vulnid "V-82137" -status NotAFinding -data $oned

        break
    }
}

if($oned -eq $null){
    stig_object -vulnid "V-82137" -status Open -data "No key found"
}elseif($oned -ne 1){
    stig_object -vulnid "V-82137" -status Open -data $oned
}

#88203
$onedg = (get-itemproperty -path 'HKlm:\SOFTWARE\Policies\Microsoft\OneDrive\AllowTenantList\' -name 1111-2222-3333-4444 -ErrorAction SilentlyContinue)."1111-2222-3333-4444"

if($onedg -eq "1111-2222-3333-4444"){
    stig_object -vulnid "V-88203" -status NotAFinding -data $onedg
}else{
    if($onedg -eq $null){
        stig_object -vulnid "V-88203" -status Open -data "No key found"
    }else{
        stig_object -vulnid "V-88203" -status Open -data $onedg
    }
}

<#
#220715
$netuser = (cmd.exe /c 'net user' 4>$null 3>$null 2>$null | where {$_ -and $_ -notmatch "command completed successfully" -and 
    $_ -notmatch "-------------------------------------------------------------------------------" -and 
    $_ -notmatch "The command completed with one or more errors."} | 
    select -Skip 1) | %{
        ($_.replace("\s+"," ")).split(" ")
    } | where{$_}

stig_object -vulnid "V-220715" -status Open -data $netuser

#63451
stig_object -vulnid "V-63451" -status Open -data ($auditpol  | %{if($_ -like "*Plug and Play Events*"){$_}})
#>

rm "$home\desktop\conf.inf" -Force -Confirm:$false | out-null