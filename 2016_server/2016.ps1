#wildcarded format for domain controllers.
$DC_name_con = "*domain_controller*"

#domain extension
$domain_ext = "dc=my,dc=domain,dc=name,dc=com"

#forest extension
$forest_ext = "dc=domain,dc=name,dc=com"

#73219
write-host ""
write-host "V-73219"

if($env:computername.substring(10,4) -like "$DC_name_con"){
    Get-ADGroupMember administrators | select name | ft -AutoSize
}else{
    write-host "NA"
}

#73221
Write-Host ""
write-host "V-73221"

if($env:computername.substring(10,4) -like "$DC_name_con"){
    write-host "NA"
}else{
    Get-LocalGroupMember administrators | ft -AutoSize
}

#73223
Write-Host ""
Write-Host "V-73223"

if($env:computername.Substring(10,4) -like "$DC_name_con"){
    get-aduser -filter * -properties sid, passwordlastset | where{$_.sid -like "*-500"} | ft -autosize name, sid, passwordlastset
}else{
    Get-LocalUser | where{$_.description -like "Built*" -and $_.enabled -eq $true} | ft -AutoSize name, sid, passwordlastset
}

#73225
Write-Host ""
write-host "V-73225"
try{
    & 'C:\Program Files\Internet Explorer\iexplore.exe'
}catch{
    write-host "Not A Finding"
}

#73227
Write-Host ""
Write-Host "V-73227"

$bousers = if($env:computername.substring(10,4) -like "$DC_name_con"){
    Get-ADGroupMember "Backup Operators" | select name
}else{
    Get-LocalGroupMember "Backup Operators"
}

if(!$bouser){
    Write-Host "No Users In 'Backup Operators'"
}else{
    $bousers
}

#73241 & 73245
Write-Host ""
write-host "V-73241 & V-73245"

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

($installed | where{$_.publisher -like "*mcafee*"}).displayname | select -Unique

#73249
Write-Host ""
write-host "V-73249"
icacls c:                       | where{$_ -and $_ -notmatch "Successfully processed"}   

#73251
Write-Host ""
write-host "V-73251"
icacls 'C:\Program Files'       | where{$_ -and $_ -notmatch "Successfully processed"}
icacls 'C:\Program Files (x86)' | where{$_ -and $_ -notmatch "Successfully processed"}

#73253
Write-Host ""
write-host "V-73253"
icacls C:\Windows               | where{$_ -and $_ -notmatch "Successfully processed"}

#73255
Write-Host ""
write-host "V-73255"

$rootKey = [Microsoft.Win32.Registry]::LocalMachine

$regkeys = "SECURITY","SOFTWARE","SYSTEM"
foreach($r in $regkeys){
    write-host ""
    write-host $r
    write-host ""

    $key = $rootKey.OpenSubKey($r, 'ReadWriteSubTree', 'ReadPermissions')

    $key.GetAccessControl().access | select IdentityReference, RegistryRights, AccessControlType, IsInherited | ft -AutoSize
}

#73257
Write-Host ""
write-host "V-73257"
$printer = Get-Printer -Full | select name, permissionsddl, shared

if($printer.shared -contains $true){

    foreach($p in ($printer | where{$_.shared -eq $true})){

        $perm = ConvertFrom-SddlString -Sddl $p.permissionsddl

        foreach($s in $perm.DiscretionaryAcl){
            [pscustomobject]@{
                Name       = $p.name
                Shared     = $p.shared
                User       = $s.split(":")[0]
                Permission = $s.split(":")[1]
            }
        }
    }
}else{
    write-host "No Shared Printers"
}

#73259
Write-Host ""
write-host "V-73259"

if($env:computername.substring(10,4) -like "$DC_name_con"){
    $inactiveusers = search-adaccount -accountinactive -usersonly -timespan 35.00:00:00 | select samaccountname

    if($inactiveusers){
        Write-Host "$($inactiveusers.count) Have Been Found."
        Write-Host 'To see all users, run: search-adaccount -accountinactive -usersonly -timespan 35.00:00:00 | select samaccountname | ft -AutoSize'
    }else{
        Write-Host "Not A Finding"
    }

}else{
    $locals = Get-LocalUser | select name, lastlogon, enabled
    $locals | ft -AutoSize
}

#73261 & 73263
Write-Host ""
write-host "V-73261 & V-73263"

if($env:computername.substring(10,4) -like "$DC_name_con"){
    $notreq = get-aduser -filter * -properties passwordnotrequired | where{$_.passwordnotrequired -eq $true -and $_.enabled -eq $true} | select name, passwordnotrequired
    $notexp = get-aduser -filter * -properties passwordneverexpires | where{ $_.passwordneverexpires -eq $true -and $_.enabled -eq $true} | select name, passwordneverexpires

    if($notreq){
        Write-Host "$($notreq.count) passwordnotrequired Have Been Found."
        Write-Host 'To see all users, run: get-aduser -filter * -properties passwordnotrequired| where{$_.passwordnotrequired -eq $true -and $_.enabled -eq $true} | select name, passwordnotrequired | ft -AutoSize'
    }else{
        Write-Host "Not A Finding"
    }

    if($notexp){
        Write-Host "$($notexp.count) passwordneverexpires Have Been Found."
        Write-Host 'To see all users, run: get-aduser -filter * -properties passwordneverexpires | where{ $_.passwordneverexpires -eq $true -and $_.enabled -eq $true} | select name, passwordneverexpires | ft -AutoSize'
    }else{
        Write-Host "Not A Finding"
    }
        

}else{
    write-host ""
    write-host "Look for flags 'Dont_Expire_Passwords' and 'PASSWD_NOTREQD'" 

    $adsi        = [ADSI]"WinNT://$env:computername"
    $allaccounts = $adsi.children | where {$_.schemaclassname -eq 'user'}

    Function Convert-UserFlag  {
        Param ($UserFlag)

        $List = New-Object System.Collections.ArrayList

        Switch ($UserFlag){
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
}

#73267
Write-Host ""
write-host "V-73267"

$folders = Get-WmiObject win32_logicalsharesecuritysetting | where {$_.name -inotlike "*$"}

if ($folders -eq $null) {
    write-host "No shares"
}else{
    $perm = Foreach ($f in $folders){
        if ($folders -eq $null) {
            write-host "No shares"
            break
        }

        foreach($a in $f.GetSecurityDescriptor().descriptor.dacl.trustee.name){
        
            $find = $f.GetSecurityDescriptor().descriptor.dacl | where{$_.trustee.name -eq $a} | select @{name="domain";expression={$_.trustee.domain}}, @{name="username";expression={$_.trustee.name}}, accessmask

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
                Name       = $f.Name
                Domain     = $find.domain
                Username   = $a
                Permission = $access
            }
        }
    }
    $perm | select name, domain, username, permission | ft -AutoSize
}

#73277
Write-Host ""
write-host "V-73277"
$feats = Get-WindowsFeature | where{$_.installed -eq $true} | select name
$feats | ft -AutoSize

#73279 & 73281
Write-Host ""
write-host "V-73279 & V-73281"

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

($installed | where{$_.publisher -like "*mcafee*"}).displayname | select -Unique

#73307
Write-Host ""
Write-Host "V-73307"

(w32tm /query /configuration | select-string "Type:*").Line

if($env:computername.substring(10,4) -like "$DC_name_con"){
    #73371
    Write-Host ""
    write-host "V-73371"
    
    icacls "c:\windows\sysvol" | where{$_ -and $_ -notmatch "Successfully processed"} 

    #73373
    Write-Host ""
    write-host "V-73373"

    $gpos           = get-gpo -All -Server $env:computername
    $permenum       = "GpoApply","GpoRead","GpoEditDeleteModifySecurity"
    $principalarray = @("ENTERPRISE DOMAIN CONTROLLERS","Authenticated Users","SYSTEM","Enterprise Admins","Domain Controllers","Domain Computers")
    
    foreach($g in $gpos){
         
         $res = $g.GetSecurityInfo()
         
         foreach($r in $res){
            if($principalarray -notcontains $r.Trustee.name){
                [pscustomobject]@{
                    GPO        = $g.DisplayName
                    Name       = $(if(!$r.trustee.name){$r.trustee.Sid.value}else{$r.trustee.name})
                    Permission = $r.permission
                }
            }else{
                if($permenum -notcontains $r.Permission){
                    [pscustomobject]@{
                        GPO        = $g.DisplayName
                        Name       = $(if(!$r.trustee.name){$r.trustee.Sid.value}else{$r.trustee.name})
                        Permission = $r.permission
                    }
                }
            }
        }
    }

    #73375
    Write-Host ""
    write-host "V-73375"

    import-module activedirectory

    $IRlist = "BUILTIN\Administrators","BUILTIN\Pre-Windows 2000 Compatible Access","CREATOR OWNER","NT AUTHORITY\Authenticated Users","NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS",
        "NT AUTHORITY\SELF","NT AUTHORITY\SYSTEM","BUILTIN\Account Operators","BUILTIN\Print Operators"

    $dcoupermlist = "CreateChild","Self","WriteProperty","ExtendedRight","Delete","GenericRead","WriteDacl","WriteOwner","ListChildren","GenericAll","DeleteChild","ReadProperty","GenericExecute"
    $dcou         = (get-acl -Path "ad:\ou=domain controllers,$domain_ext" | select -ExpandProperty access) | select IdentityReference, ActiveDirectoryRights -Unique | sort IdentityReference

    $dcouperms = foreach($d in ($dcou.IdentityReference | get-unique).value){
        if(($dcou | where{$_.IdentityReference -eq $d}).count -gt 1){
            [pscustomobject]@{
                IdentityReference     = $d
                ActiveDirectoryRights = ((($dcou | where{$_.IdentityReference -eq $d}).activedirectoryrights -join ", ").split(",") | Get-Unique) -join ","
            }
        }else{
            $dcou | where{$_.IdentityReference -eq $d}
        }
    }

    $dcoures = foreach($d in $dcouperms){
        if($IRlist -notcontains $d.IdentityReference){
            $d
        }else{
            
            try{
                $splits = ($d.ActiveDirectoryRights).Split(",").replace(" ","")
            }catch{
                continue
            }

            foreach($p in $splits){
                if($dcoupermlist -notcontains $p){
                    [pscustomobject]@{
                        IdentityReference     = $d.IdentityReference
                        ActiveDirectoryRights = $p
                    }
                }
            }
        }
    }

    $dcoures | ft -AutoSize

    #73377
    Write-Host ""
    write-host "V-73377"

    $builtinou = (Get-ADObject -SearchScope OneLevel -Filter * -Properties isCriticalSystemObject | where{$_.isCriticalSystemObject -eq $true}).distinguishedname
    
    foreach($b in $builtinou){

        $ou = (get-acl -Path "ad:\$b" | select -ExpandProperty access) | select IdentityReference, ActiveDirectoryRights -Unique | sort IdentityReference

        $ouperms = foreach($d in ($ou.IdentityReference | get-unique).value){
            if(($ou | where{$_.IdentityReference -eq $d}).count -gt 1){
                [pscustomobject]@{
                    IdentityReference     = $d
                    ActiveDirectoryRights = ((($ou | where{$_.IdentityReference -eq $d}).activedirectoryrights -join ", ").split(",") | Get-Unique) -join ","
                    ou                    = $b
                }
            }else{
                $ou | where{$_.IdentityReference -eq $d}
            }
        }
    }

    $builtinoures = foreach($d in $ouperms){
        if($IRlist -notcontains $d.IdentityReference){
            $d
        }else{

            try{
                $splits = ($d.ActiveDirectoryRights).Split(",").replace(" ","")
            }catch{
                continue
            }

            foreach($p in $splits){
                if($dcoupermlist -notcontains $p){
                    [pscustomobject]@{
                        IdentityReference     = $d.IdentityReference
                        ActiveDirectoryRights = $p
                        ou                    = $d.ou
                    }
                }
            }
        }
    }

    $builtinoures | ft -AutoSize
    
    #73379
    Write-Host ""
    write-host "V-73379"

    $ntds = ((get-itemproperty -path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -name "DSA Database file" -ErrorAction SilentlyContinue)."DSA Database file").split(":")[0]

    if(gwmi win32_share | where{$_.name -notlike "*$" -and $_.path -like "$($ntds)*"}){
        Write-Host ""
        write-host "Finding! Move User Shares"
        gwmi win32_share | where{$_.name -notlike "*$" -and $_.path -like "$($ntds)*"}
    }

    #73381
    Write-Host ""
    write-host "V-73381"

    Get-WindowsFeature | where{$_.InstallState -eq "Installed"} | ft -AutoSize

    write-host ""

    $list = @()
    $list += get-itemproperty hklm:\software\wow6432node\microsoft\windows\currentversion\uninstall\* | where {$_.displayname -ne $null} | select displayname
    $list += get-itemproperty hklm:\software\microsoft\windows\currentversion\uninstall\* | where {$_.displayname -ne $null} | select displayname

    $list | sort displayname | ft -AutoSize

    #73385
    Write-Host ""
    write-host "V-73385"

    [System.Reflection.Assembly]::LoadWithPartialName("system.directoryservice.protocols")
    [System.Reflection.Assembly]::LoadWithPartialName("system.net") | Out-Null

    $ldapobj = New-Object System.DirectoryServices.Protocols.LdapConnection "$((Get-NetIPAddress | where{$_.InterfaceAlias -notlike "Loopback*"}).IPAddress):389"
    $ldapobj.AuthType = [System.DirectoryServices.Protocols.AuthType]::Anonymous
    $ldapobj.SessionOptions.SecureSocketLayer = $false
    $ldapobj.SessionOptions.ProtocolVersion   = 3

    $scope                                    = [System.DirectoryServices.Protocols.SearchScope]::OneLevel
    $attributelist                            = @("*")

    $req = New-Object System.DirectoryServices.Protocols.SearchRequest -ArgumentList "$domain_ext","(objectclass=*)",$scope,$attributelist

    try {
        $resp = $ldapobj.SendRequest($req)

        write-host "Finding"
    }catch{
        write-host "Cant Anon Bind / Search"
    }

    #73387
    Write-Host ""
    write-host "V-73387"

    $searchbase = "CN=Query-Policies,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$forest_ext"
    ((get-adobject -SearchBase $searchbase -filter 'Objectclass -eq "queryPolicy" -and Name -eq "Default Query Policy"' -Properties *).lDAPAdminLimits | Select-String "MaxConnIdleTime").line

    #73389
    Write-Host ""
    write-host "V-73389"

    $allgpopath = Get-GPO -all | select displayname, path
    $badaudits = foreach($a in $allgpopath){
        
        $audit = (Get-Acl -Audit -path AD:\$($a.path)).Audit | select identityreference, auditflags, ActiveDirectoryRights, InheritanceFlags 
        
        if(($audit | where{$_.identityreference -ne "Everyone"}).count -gt 0 -or $audit.count -ne 6){

            foreach($t in $audit){
                [pscustomobject]@{
                    Name                  = $a.displayname
                    IdentityReference     = $t.IdentityReference
                    AuditFlags            = $t.auditflags
                    ActiveDirectoryRights = $t.ActiveDirectoryRights
                    InheritanceFlags      = $t.InheritanceFlags
                }
            }
        }else{
            
            $scount = ($audit.auditflags | where{$_ -eq "Success"}).count
            $fcount = ($audit.auditflags | where{$_ -eq "Failure"}).count
            $ccount = ($audit.auditflags | where{$_ -eq "Success, Failure"}).count

            if($scount -ne 4 -or $fcount -ne 1 -or $ccount -ne 1){
                foreach($t in $audit){
                    [pscustomobject]@{
                        Name                  = $a.displayname
                        IdentityReference     = $t.IdentityReference
                        AuditFlags            = $t.auditflags
                        ActiveDirectoryRights = $t.ActiveDirectoryRights
                        InheritanceFlags      = $t.InheritanceFlags
                    }
                }
            }
        }             
    }

    if($badaudits){
        $badaudits | ft -AutoSize
    }else{
        Write-Host "No Bad Audit Settings Found"
    }

    #73391
    Write-Host ""
    write-host "V-73391"
    
    (Get-Acl -Audit -path "AD:\$domain_ext").Audit | select identityreference, auditflags, ActiveDirectoryRights, InheritanceFlags  | ft -AutoSize

    #73393
    Write-Host ""
    write-host "V-73393"

    (Get-Acl -Audit -path "AD:\CN=Infrastructure,$domain_ext").Audit | select identityreference, auditflags, ActiveDirectoryRights, InheritanceFlags  | ft -AutoSize

    #73395
    Write-Host ""
    write-host "V-73395"

    (Get-Acl -Audit -path "AD:\OU=Domain Controllers,$domain_ext").Audit | select identityreference, auditflags, ActiveDirectoryRights, InheritanceFlags  | ft -AutoSize

    #73397
    Write-Host ""
    write-host "V-73397"

    (Get-Acl -Audit -path "AD:\CN=AdminSDHolder,CN=System,$domain_ext").Audit | select identityreference, auditflags, ActiveDirectoryRights, InheritanceFlags  | ft -AutoSize

    #73399
    Write-Host ""
    write-host "V-73399"

    (Get-Acl -Audit -path "AD:\CN=RID Manager$,CN=System,$domain_ext").Audit | select identityreference, auditflags, ActiveDirectoryRights, InheritanceFlags  | ft -AutoSize

    #73417
    Write-Host ""
    write-host "V-73417"

    (auditpol /get /category:* | select-string "Computer Account Management").Line

}else{
    write-host ""
    Write-Host "NA: V-73371, V-73373, V-73375, V-73377, V-73379, V-73381, V-73383, V-73385, V-73387, V-73389, V-73391, V-73393, V-73395, V-73397, V-73399, V-73417"
}

#73431
Write-Host ""
Write-Host "V-73431"

(auditpol /get /category:* | select-string "Plug and Play Events").Line

#73447
Write-Host ""
write-host "V-73447"

(auditpol /get /category:* | select-string "Group Membership").Line

#73457 & 73459
Write-Host ""
Write-Host "V-73457 & V-73459"

(auditpol /get /category:* | select-string "Removable Storage").Line

#73513 & 73515
Write-Host ""
write-host "V-73513 & 73515"
write-host "SecurityServicesRunning for DC is NA"

Get-CimInstance win32_deviceguard -Namespace root\microsoft\windows\deviceguard | select RequiredSecurityProperties, VirtualizationBasedSecurityStatus, SecurityServicesRunning | ft -AutoSize

if($env:computername.substring(10,4) -like "$DC_name_con"){
    #73611
    Write-Host ""
    Write-Host "V-73611"

    $dccerts = gci Cert:\LocalMachine\My

    if($dccerts){
        Write-Host "DC Certs Are Good"
    }else{
        Write-Host "Finding"
    }

    #73613
    Write-Host ""
    Write-Host "V-73613"

    if($dccerts[0].Issuer -like "*OU=ORG, OU=PKI, OU=DoD, O=U.S. Government, C=US"){
        Write-Host "CA is Valid"
    }else{
        Write-Host "CA is Inalid"
    }

    #73615
    Write-Host ""
    Write-Host "V-73615"

    $nocac = get-aduser -filter * | where{$_.Enabled -eq $true -and $_.userprincipalname -notmatch "[0-9]{10}@"} | select userprincipalname

    Write-Host "$($nocac.count) User(s) found without a CAC mapping."
    Write-Host 'Run this to show all users: get-aduser -filter * | where{$_.Enabled -eq $true -and $_.userprincipalname -notmatch "[0-9]{10}@"} | select userprincipalname'

    #73617
    Write-Host ""
    Write-Host "V-73617"

    $smartcard = get-aduser -filter * -Properties SmartcardLogonRequired | where{$_.Enabled -eq $true -and $_.SmartcardLogonRequired -eq $false} | select samaccountname

    Write-Host "$($smartcard.count) User(s) found without a SmartCard requirment."
    Write-Host 'Run this to show all users: get-aduser -filter * -Properties SmartcardLogonRequired | where{$_.Enabled -eq $true -and $_.SmartcardLogonRequired -eq $false} | select samaccountname'
}else{
    Write-Host " MS is NA for V-73611, V-73613, V-73615, V-73617"
}

#73665
Write-Host ""
Write-Host "V-73665"

secedit /export /cfg "$home\desktop\conf.inf" | out-null
$sec = Get-Content "$home\desktop\conf.inf"
($sec | select-string "LSAAnonymousNameLookup").Line | ft -AutoSize

#73727
Write-Host ""
Write-Host "V-73727"

$zone = (get-itemproperty -path 'HKcu:\software\microsoft\windows\currentversion\policies\attachments' -name savezoneinformation -ErrorAction SilentlyContinue).savezoneinformation 

if($zone -eq $null){
    write-host "No key found"
}else{
    $zone | ft -AutoSize
}

#78127
Write-Host ""
Write-Host "V-78127"

$matches = ([regex]::matches($sec,"(S(-\d+){2,8})")).value
write-host "Unresolved SID's below, please remove them."
Write-Host ""
$unsid = foreach($m in $matches | where{$_.length -gt "12" -and $_ -notlike "*-512" -and $_ -notlike "*-519"} | select -Unique){
    
    $objSID  = New-Object System.Security.Principal.SecurityIdentifier ("$m")
    $objUser = ($objSID.Translate([System.Security.Principal.NTAccount])).value
    
    if(!$objUser){
        ($sec | select-string $m) | %{$_.ToString().Split(" = ")[0]} | %{
            [pscustomobject]@{
                right = $_
                sid   = $m
            }
        }
    }
}

$unsid | ft -AutoSize

#90355
Write-Host ""
Write-Host "V-90355"

write-host "Secure Boot = $(Confirm-SecureBootUEFI)"

#90357
Write-Host ""
Write-Host "V-90357"

$og = $ProgressPreference
$ProgressPreference = "SilentlyContinue"
get-computerinfo | select BiosFirmwareType | ft -AutoSize
$ProgressPreference = $og

if($env:computername.substring(10,4) -like "$DC_name_con"){
    #91779
    Write-Host ""
    Write-Host "V-91779"

    $dayspast = ((Get-Date) - (get-aduser krbtgt -Properties passwordlastset).passwordlastset).days

    if($dayspast -gt 180){
        Write-Host "Finding, $dayspast Days Since Last Set."
    }else{
        Write-Host "Not A Finding"
    }
}else{
    Write-Host "V-91779 is NA for MS"
}

rm "$home\desktop\conf.inf" -Force -Confirm:$false | out-null
