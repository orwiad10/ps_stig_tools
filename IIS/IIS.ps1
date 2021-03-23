$sitename = ((Get-IISServerManager).sites | where{$_.name -ne "Default Web Site"}).name

$iisfeat = Get-ItemProperty hklm:\Software\Microsoft\inetstp\components
$names = ($iisfeat  | Get-Member | where{$_.membertype -eq "noteproperty"}).name

$iisfeatureslist = $(foreach($n in $names){
    [pscustomobject]@{
        Displayname = $n
        Value       = $iisfeat.$n
    }
}) | where{$_.value -eq 1}

#IIST-SV-000102 & #IIST-SV-000111
Write-Host "IIST-SV-000102 & #IIST-SV-000111"

$iislogval = ((Get-IISSite "$sitename").childelements | where{$_.ElementTagName -eq "logfile"}).RawAttributes["logExtFileFlags"]

if([int]$iislogval -ge 329359){
    Write-Host "Not A Finding"
}else{
    Write-Host "Finding"
}

#IIST-SV-000103
Write-Host ""
Write-Host "IIST-SV-000103"

Get-WebConfigurationProperty -Filter 'system.applicationhost/sites/sitedefaults/logfile' -name logtargetw3c

#IIST-SV-000110 & #IIST-SV-000111
Write-Host ""
Write-Host "IIST-SV-000110 & #IIST-SV-000111"

Get-WebConfigurationProperty -filter "system.applicationhost/sites/site[@name=`"$sitename`"]/logfile/customfields" -Name collection

#IIST-SV-000115
Write-Host ""
Write-Host "IIST-SV-000115"

$logpath = ((Get-IISSite "$sitename").childelements | where{$_.ElementTagName -eq "logfile"}).RawAttributes["directory"]

$logpath = $logpath.Replace("%SystemDrive%","C:\")

foreach($l in (gci $logpath)){
    icacls $l.fullname | select -SkipLast 1
}

#IIST-SV-000118
Write-Host ""
Write-Host "IIST-SV-000118"

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

$installed | where{$_.displayname -ne $null} | sort displayname | ft -AutoSize

#IIST-SV-000119
Write-Host ""
Write-Host "IIST-SV-000119"

$arr = Get-WebConfigurationProperty -Filter 'system.webserver/proxy' -name "enabled"

if($arr){
    write-host $arr
}else{
    write-host "Not A Finding"
}

$exfiles  = @()
$exfiles += gci "C:\Program Files (x86)\Common Files\System\msadc" -Recurse -force | select name
$exfiles += gci "C:\Program Files\Common Files\System\msadc" -Recurse -force | select name
$exfiles += gci "C:\inetpub" -Recurse -force | select name

$exfiles | where{$_.name -notlike "*.tmp" -and 
    $_.name -notlike "*.log" -and $_.name -notlike "*.config" -and 
    $_.name -notlike "*.mui" -and $_.name -notlike "*.png" -and $_.name -like "*.*"
} | ft -AutoSize

#IIST-SV-000121
Write-Host ""
Write-Host "IIST-SV-000121"

Get-LocalUser | select name | ft -AutoSize

#IIST-SV-000124
Write-Host ""
Write-Host "IIST-SV-000124"

$mime = ((Get-WebConfigurationProperty //staticcontent -name ".").collection).fileextension

$exts = ".exe",".dll",".com",".bat",".csh"

foreach($e in $exts){
    if($mime.contains($e)){
        Write-Host "$e Found"
    }
}

#IIST-SV-000125
Write-Host ""
Write-Host "IIST-SV-000125"

if($iisfeatureslist | where{$_.displayname -like "*webdav*"}){
    write-host "Finding"
}else{
    write-host "Not A Finding"
}

#IIST-SV-000129
Write-Host ""
Write-Host "IIST-SV-000129"

gci Cert:\LocalMachine\My | select thumbprint, issuer | ft -autosize

#IIST-SV-000130
Write-Host ""
Write-Host "IIST-SV-000130"

$javafiles = & cmd.exe /c "dir c:\ /A-D /S /B"
$foundjava = $javafiles | where{$_ -like "*.java" -or $_ -like "*.jpp"}
$foundjava | ft -AutoSize

#IIST-SV-000137
Write-Host ""
Write-Host "IIST-SV-000137"

$machinekeyfiles = $javafiles | where{$_ -like "*machine.config" -and $_ -notlike "c:\Windows\WinSxS*"}

$machinekeys = @()

foreach($m in $machinekeyfiles){
    $xmlmachineconf = [xml](Get-Content $m)

    $systemweb = $xmlmachineconf.get_documentelement().'system.web'

    $machinekeys += $systemweb.machinekey
}

if(!$machinekeys){
    Write-Host "No Keys Found"
}else{
    $machinekeys | ft -AutoSize
}

#################################

#IIST-SV-000205
Write-Host ""
Write-Host "IIST-SV-000205"

$sc = Get-IISConfigSection -SectionPath "system.applicationHost/sites" | Get-IISConfigCollection
$se = Get-IISConfigCollectionElement -ConfigCollection $sc -ConfigAttribute @{"name"="WSUS Administration"}

try{
    $hsts = Get-IISConfigElement -ConfigElement $se -ChildElementName "hsts"
}catch{
    write-host "No HSTS Found"
}
