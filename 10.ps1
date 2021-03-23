$buildnum = (get-itemproperty -path 'HKlm:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -name ReleaseId -ErrorAction SilentlyContinue).ReleaseId

#63323
Write-Output ""
write-output "V-63323"

(Get-Tpm).tpmready

#63343
Write-Output ""
write-output "V-63343"

Get-BitLockerVolume | select mountpoint, volumestatus, encryptionpercentage, protectionstatus

#63343
Write-Output ""
write-output "V-63343"

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

($installed | where{$_.publisher -like "*mcafee*"}).displayname

#63345
Write-Output ""
write-output "V-63345"

Get-AppLockerPolicy -Effective -XML

#63355
Write-Output ""
write-output "V-63355"

$cxOptions = new-object System.Management.ConnectionOptions
$cxOptions.Impersonation=[System.Management.ImpersonationLevel]::Impersonate
$cxOptions.EnablePrivileges=$true

$mgmtScope   = new-object System.Management.ManagementScope -ArgumentList "root\WMI",$cxOptions
$mgmtPath    = new-object System.Management.ManagementPath -ArgumentList 'root\WMI:BcdObject.Id="{9dea862c-5cdd-4e70-acc1-f32b344d4795}",StoreFilePath=""'
$mgmtObject  = new-object System.Management.ManagementObject -ArgumentList $mgmtScope,$mgmtPath,$null
$objBCD      = $mgmtObject.GetElement(0x24000001)
$objElements = $objBCD.GetPropertyValue("Element")

$strOldID="{9dea862c-5cdd-4e70-acc1-f32b344d4795}"
for ($i=0; $i -lt $objElements.Ids.Count; $i++) {
  $mgmtPath.Path = $mgmtPath.Path.Replace($strOldID,$objElements.Ids[$i])
  $strOldID      = $objElements.Ids[$i]
  $objBCDId      = new-object System.Management.ManagementObject -ArgumentList $mgmtScope,$mgmtPath,$null
  $strOS         = $objBCDId.GetElement(0x12000004)
  $strOS.Element.String
}

#63357
Write-Output ""
write-output "V-63357"

$folders = Get-WmiObject win32_logicalsharesecuritysetting | where {$_.name -inotlike "*$"}

if ($folders -eq $null) {
    Write-Output "No shares"
}else{
    $perm = Foreach ($f in $folders){
        if ($folders -eq $null) {
            Write-Output "No shares"
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
    $perm | select name, domain, username, permission | ft -AutoSize
}

#63359
Write-Output ""
write-output "V-63359"

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
        lastlogin = $LLO
        enabled   = $enabled
    }
}

$user | select name, lastlogin, enabled | ft -AutoSize

#63361
Write-Output ""
write-output "V-63361"

$users = cmd.exe /c "net localgroup administrators" | where {$_ -and $_ -notmatch "command completed successfully"} | select -skip 4
$out = foreach($u in $users){
    [pscustomobject]@{
        User = $u
    }
}
$out | ft -AutoSize

#63363
Write-Output ""
write-output "V-63363"

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

#63365
Write-Output ""
write-output "V-63365"

$users3 = cmd.exe /c 'net localgroup "Hyper-V Administrators"' | where {$_ -and $_ -notmatch "command completed successfully"} | select -skip 4
if($user3 -eq $null -or $user3 -eq ""){
    Write-Output ""
    Write-Output "No Users in Hyper-V Administrators Group"
}else{
    $out3 = foreach($u in $users3){
        [pscustomobject]@{
            User = $u
        }
    }
    $out3 | ft -AutoSize
}

#63367
Write-Output ""
write-output "V-63367"

(cmd.exe /c 'net user' | where {$_ -and $_ -notmatch "command completed successfully" -and 
    $_ -notmatch "-------------------------------------------------------------------------------" -and 
    $_ -notmatch "The command completed with one or more errors."} | 
    select -Skip 1) |
    %{($_.replace("\s+"," ")).split(" ")} | 
    where{$_}

#63371
Write-Output ""
write-output "V-63371"

$adsi = [ADSI]"WinNT://$env:computername"
$allaccounts = $adsi.children | where { $_.schemaclassname -eq 'user' }

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

$users = foreach ($a in $allaccounts){
    $UserFlag = $a.UserFlags.value

    [pscustomobject]@{
        Name = $a.Name
        Flags = Convert-UserFlag -UserFlag $Userflag
    }
}

$users | select name, flags | ft -AutoSize

#63373
Write-Output ""
write-output "V-63373"

"c:\","c:\program files","c:\windows" | %{icacls $_ | select -SkipLast 1}

#63393
Write-Output ""
write-output "V-63393"
<#
    $drives = (Get-Volume | where{$_.DriveLetter -ne $null}).driveletter

    function FilesRecursive{
        Param(
            [parameter(Mandatory = $true, Position = 0)]
            [string]$Path,
            [parameter(Mandatory = $true, Position = 1)]
            [string]$Filter
        )

        $SB_recursive = {
            [System.IO.Directory]::Getdirectories($args[0]) | ForEach-Object {
                Try{
                    ([System.IO.Directory]::enumeratefiles($_,$Filter,'alldirectories'))
                }Catch [UnauthorizedAccessException],[System.Management.Automation.CmdletInvocationException]{
                    $i = 0
                }

                Try{
                    $SB_recursive.Invoke($_)
                }Catch [UnauthorizedAccessException],[System.Management.Automation.CmdletInvocationException]{
                }
            }
        }
        $SB_recursive.Invoke($Path)
    }
    
    [System.Collections.ArrayList]$files = foreach ($d in $drives){
        FilesRecursive -path "$d`:\" -filter '*.*'
    }
    
    $files.Where({$_ -match '.+?pfx$'})
    $files.Where({$_ -match '.+?p12$'})
 #>

write-output "Scheduled Task Output"

#63451
Write-Output ""
write-output "V-63451"

Invoke-Command -ScriptBlock {auditpol /get /category:*} | %{if($_ -like "*Plug and Play Events*"){write-host $_}}

#63457
Write-Output ""
write-output "V-63457"

Invoke-Command -ScriptBlock {auditpol /get /category:*} | %{if($_ -like "*Group Membership*"){write-host $_}}

#63471 and 63473
Write-Output ""
write-output "V-63471 and 63473"

Invoke-Command -ScriptBlock {auditpol /get /category:*} | %{if($_ -like "*Removable Storage*"){write-host $_}}

#63545
Write-Output ""
write-output "V-63545"

$lockscreen = (get-itemproperty -path 'HKlm:\SOFTWARE\Policies\Microsoft\Windows\Personalization\' -name NoLockScreenCamera -ErrorAction SilentlyContinue).NoLockScreenCamera

if ($lockscreen -eq $null){
    write-output "No key found"
}else{
    $lockscreen
}

#63587
Write-Output ""
write-output "V-63587"

Get-ChildItem -Path Cert:Localmachine\disallowed | Where {$_.Issuer -Like "*DoD Interoperability*" -and $_.Subject -Like "*DoD*"} | FL Subject, Issuer, Thumbprint, NotAfter

#63593
Write-Output ""
write-output "V-63593"

$rootKey = [Microsoft.Win32.Registry]::LocalMachine

$regkeys = "SECURITY","SOFTWARE","SYSTEM"
foreach($r in $regkeys){
    write-output ""
    write-output $r
    write-output ""

    $key = $rootKey.OpenSubKey($r, 'ReadWriteSubTree', 'ReadPermissions')

    $key.GetAccessControl().access | select IdentityReference, RegistryRights, AccessControlType, IsInherited | ft -AutoSize
}

#63595, 63599, 63603
Write-Output ""
write-output "V-63595, V-63599, V-63603"

Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | select RequiredSecurityProperties, VirtualizationBasedSecurityStatus, SecurityServicesRunning

#63717
Write-Output ""
write-output "V-63717"

$psp = (get-itemproperty -path 'HKlm:\SOFTWARE\Policies\Microsoft\PassportForWork\' -name RequireSecurityDevice -ErrorAction SilentlyContinue).RequireSecurityDevice

if ($psp -eq $null){
    write-output "No key found"
}else{
    $psp
}

#63739
Write-Output ""
write-output "V-63739"

secedit /export /cfg "$home\desktop\conf.inf" | out-null
$sec = Get-Content "$home\desktop\conf.inf"
($sec | select-string "LSAAnonymousNameLookup").Line

#63839
Write-Output ""
Write-Output "V-63839"

$to = (get-itemproperty -path 'HKcu:\software\policies\microsoft\windows\currentversion\pushnotifications\' -name NoToastApplicationNotificationOnLockscreen -ErrorAction SilentlyContinue).NoToastApplicationNotificationOnLockscreen

if ($to -eq $null){
    write-output "No key found"
}else{
    $to
}

#63841
Write-Output ""
Write-Output "V-63841"

$zone = (get-itemproperty -path 'HKcu:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments\' -name SaveZoneInformation -ErrorAction SilentlyContinue).SaveZoneInformation

if ($zone -eq $null){
    write-output "No key found"
}else{
    $zone
}

#72765 & 67
Write-Output ""
Write-Output "V-72765 & V-72767"


$bluetooth = Get-WmiObject Win32_PnPEntity | WHERE{$_.ConfigManagerErrorCode -eq 0 -and $_.caption -like "*bluetooth*"} | select caption

if(!$blutooth){
    Write-Output "No Bluetooth Found"
}else{
    $bluetooth | ft -AutoSize
}

#72769
Write-Output ""
Write-Output "V-72769"

Write-Output ""
Write-Output " If `"No Bluetooth Found`", This is NA. If not, do this check."

#63841
Write-Output ""
Write-Output "V-63841"

$ecc = (get-itemproperty -path 'HKlm:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002\' -name EccCurves -ErrorAction SilentlyContinue).EccCurves

if ($ecc -eq $null){
    write-output "No key found"
}else{
    $ecc
}

#76505
Write-Output ""
Write-Output "V-76505"

$matches = ([regex]::matches($sec,"(S(-\d+){2,8})")).value
Write-Output "Unresolved SID's below, please remove them."
foreach($m in $matches | where{$_.length -gt "12" -and $_ -notlike "*-512" -and $_ -notlike "*-519"} | select -Unique){
    
    $objSID = New-Object System.Security.Principal.SecurityIdentifier ("$m")
    $objUser = ($objSID.Translate( [System.Security.Principal.NTAccount])).value
    
    if(!$objUser){
        ($sec | select-string $m) | %{$_.ToString().Split(" = ")[0]} | %{
            [pscustomobject]@{
                right = $_
                sid = $m
            }
        }
    }
}

#77083
Write-Output ""
Write-Output "V-77083"

$d = Confirm-SecureBootUEFI -ErrorVariable ProcessError
if($ProcessError -eq $true){
    Write-Output "Legacy"
}else{
    Write-Output "UEFI"
}

#77085
Write-Output ""
Write-Output "V-77085"

$secboot = Confirm-SecureBootUEFI

Write-Output ""
Write-Output "Secure Boot = $secboot"

#77091
Write-Output ""
Write-Output "V-77091"
Write-Output ""

if($buildnum -le 1607){
    "NA"
}else{
    #todo
}

<#
[int]$dep = ((wmic OS Get DataExecutionPrevention_SupportPolicy) | Select-String -allmatches '0|1|2|3').Matches[0].Value

switch($dep){
    0       {"DEP OFF"}
    1       {"DEP ON"}
    2       {"DEP NOT SET"}
    3       {"DEP ON"}
    Defualt {"Check DEP By Hand"}
}#>

#77095
Write-Output ""
Write-Output "V-77095"
Write-Output ""

if($buildnum -le 1607){
    "NA"
}else{
    #todo
}

#77097
Write-Output ""
Write-Output "V-77097"
Write-Output ""

if($buildnum -le 1607){
    "NA"
}else{
    #todo
}

#77101
Write-Output ""
Write-Output "V-77101"
Write-Output ""

if($buildnum -le 1607){
    "NA"
}else{
    #todo
}

#77103
Write-Output ""
Write-Output "V-77103"
Write-Output ""

if($buildnum -le 1607){
    "NA"
}else{
    #todo
}

#77189
Write-Output ""
Write-Output "V-77189"
Write-Output ""

if($buildnum -le 1607){
    "NA"
}else{
    #todo
}

#77191
Write-Output ""
Write-Output "V-77191"
Write-Output ""

if($buildnum -le 1607){
    "NA"
}else{
    #todo
}

#77195
Write-Output ""
Write-Output "V-77195"
Write-Output ""

if($buildnum -le 1607){
    "NA"
}else{
    #todo
}

#77201
Write-Output ""
Write-Output "V-77201"
Write-Output ""

if($buildnum -le 1607){
    "NA"
}else{
    #todo
}

#77205
Write-Output ""
Write-Output "V-77205"
Write-Output ""

if($buildnum -le 1607){
    "NA"
}else{
    #todo
}

#77209
Write-Output ""
Write-Output "V-77209"
Write-Output ""

if($buildnum -le 1607){
    "NA"
}else{
    #todo
}

#77213
Write-Output ""
Write-Output "V-77213"
Write-Output ""

if($buildnum -le 1607){
    "NA"
}else{
    #todo
}

#77217
Write-Output ""
Write-Output "V-77217"
Write-Output ""

if($buildnum -le 1607){
    "NA"
}else{
    #todo
}

#77221
Write-Output ""
Write-Output "V-77221"
Write-Output ""

if($buildnum -le 1607){
    "NA"
}else{
    #todo
}

#77223
Write-Output ""
Write-Output "V-77223"
Write-Output ""

if($buildnum -le 1607){
    "NA"
}else{
    #todo
}

#77227
Write-Output ""
Write-Output "V-77227"
Write-Output ""

if($buildnum -le 1607){
    "NA"
}else{
    #todo
}

#77231
Write-Output ""
Write-Output "V-77231"
Write-Output ""

if($buildnum -le 1607){
    "NA"
}else{
    #todo
}

#77233
Write-Output ""
Write-Output "V-77233"
Write-Output ""

if($buildnum -le 1607){
    "NA"
}else{
    #todo
}

#77235
Write-Output ""
Write-Output "V-77235"
Write-Output ""

if($buildnum -le 1607){
    "NA"
}else{
    #todo
}

#77239
Write-Output ""
Write-Output "V-77239"
Write-Output ""

if($buildnum -le 1607){
    "NA"
}else{
    #todo
}

#77245
Write-Output ""
Write-Output "V-77245"
Write-Output ""

if($buildnum -le 1607){
    "NA"
}else{
    #todo
}

#77247
Write-Output ""
Write-Output "V-77247"
Write-Output ""

if($buildnum -le 1607){
    "NA"
}else{
    #todo
}

#77249
Write-Output ""
Write-Output "V-77249"
Write-Output ""

if($buildnum -le 1607){
    "NA"
}else{
    #todo
}

#77255
Write-Output ""
Write-Output "V-77255"
Write-Output ""

if($buildnum -le 1607){
    "NA"
}else{
    #todo
}

#77259
Write-Output ""
Write-Output "V-77259"
Write-Output ""

if($buildnum -le 1607){
    "NA"
}else{
    #todo
}

#77263
Write-Output ""
Write-Output "V-77263"
Write-Output ""

if($buildnum -le 1607){
    "NA"
}else{
    #todo
}

#77267
Write-Output ""
Write-Output "V-77267"
Write-Output ""

if($buildnum -le 1607){
    "NA"
}else{
    #todo
}

#77269
Write-Output ""
Write-Output "V-77269"
Write-Output ""

if($buildnum -le 1607){
    "NA"
}else{
    #todo
}

#78129
Write-Output ""
Write-Output "V-78129"
Write-Output ""

Get-Process | where{$_.name -eq "iexplore"} | Stop-Process -Force

try{
    Start-Process -FilePath 'C:\Program Files\Internet Explorer\iexplore.exe' -ErrorVariable ieerror -Credential (Get-Credential -Message "Enter ADMIN Credentials" -UserName "j-cre\") -NoNewWindow | out-null
    Get-Process | where{$_.name -eq "iexplore"} | Stop-Process -Force
}catch{
    $ieerror
}

#82137
Write-Output ""
Write-Output "V-82137"

$oned = (get-itemproperty -path 'HKcu:\Software\Policies\Microsoft\OneDrive\' -name DisablePersonalSync -ErrorAction SilentlyContinue).DisablePersonalSync

if ($oned -eq $null){
    write-output "No key found"
}else{
    $oned
}

#88203
Write-Output ""
Write-Output "V-88203"

$onedg = (get-itemproperty -path 'HKlm:\SOFTWARE\Policies\Microsoft\OneDrive\AllowTenantList\' -name 1111-2222-3333-4444 -ErrorAction SilentlyContinue)."1111-2222-3333-4444"

if ($onedg -eq $null){
    write-output "No key found"
}else{
    $onedg
}

#94719
Write-Output ""
Write-Output "V-94719"

$ap = (get-itemproperty -path 'HKlm:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy\' -name LetAppsActivateWithVoiceAboveLock -ErrorAction SilentlyContinue).LetAppsActivateWithVoiceAboveLock

if ($ap -eq $null){
    write-output "No key found"
}else{
    $ap
}

rm "$home\desktop\conf.inf" -Force -Confirm:$false