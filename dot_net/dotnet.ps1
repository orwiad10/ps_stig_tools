#V1R9

function stig_object {
    param(
        $vulnid,
        [ValidateSet('Finding','NotAFinding')]
        $status,
        $data
    )

    [pscustomobject]@{
        VulnID = $vulnid
        Status = $status
        Data   = $data
    }
}

$dotnet = & cmd.exe /c "dir c:\ /A-D /b /s" 4>$null 3>$null 2>$null

$dotnet = $dotnet | where{$_ -like "*machine.config" -or $_ -like "*exe.config"}

if($dotnet -eq $null){
    throw "GCI Failed"
}

#7055
write-host "V-7055"
$StrN = Test-Path HKLM:\SOFTWARE\Microsoft\strongname\verification
$7055stat = if($StrN -eq $false){
    "NotAFinding"
}else{
    "Finding"
}

stig_object -vulnid "V-7055" -status $7055stat

#7063
$check = c:\windows\Microsoft.NET\Framework64\v4.0.30319\caspol.exe -m -lg | select-string -pattern "1.6"


if($check -eq $null -or $check -eq ""){
    $7063data = $null
}else{
    $7063data = $check | select line
}

stig_object -vulnid "V-7063" -status Finding -data $7063data -depth 2 -format Custom

#7067
$check1 = c:\windows\Microsoft.NET\Framework64\v4.0.30319\caspol.exe -all -lg | select-string -pattern "strongname"

if($check1 -eq $null -or $check1 -eq "") {
    $7067data = $null
}else{
    $7067data = $check1 | select line
}

$s = stig_object -vulnid "V-7067" -status "Finding" -data $7067data -depth 2 -format Custom

#7070
$chan = $(foreach($d in $dotnet){
    get-content $d | where{$_ -like '*channel ref=*' } | select @{n = "Path"; e = {$d}}, @{n = "Match"; e = {$_}}
})

if($chan){
    $7070data = $chan
}else{
    $7070data = $null
}

stig_object -vulnid "V-7070" -status "Finding" -data $7070data -format None

#18395
stig_object -vulnid "V-18395" -status "Finding" -data ((Get-ChildItem C:\windows\Microsoft.NET\F* -Recurse -force | where{$_.Name -eq "Mscorlib.dll"} ).VersionInfo | where{$_.internalname -eq "Mscorlib.dll"} | select filename, productversion) -depth 2 -format Custom

#30935
$bypass1 = try{
    (get-itemproperty -path HKLM:\SOFTWARE\Microsoft\.NETFramework -name allowstrongnamebypass -ErrorAction Stop).allowstrongnamebypass
}catch{}

$bypass2 = try{
    (get-itemproperty -path hklm:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework -ErrorAction Stop).allowstrongnamebypass
}catch{}

if($bypass1 -and $bypass2){
    $30935data = "$bypass1 & $bypass2"
}elseif($bypass1 -or $bypass2){
    if($bypass1){
        $30935data = $bypass1
    }else{
        $30935data = $bypass1
    }
}else{
    $30935data = "No Data Found"
}

stig_object -vulnid "V-30935" -status "Finding" -data $30935data -format None

#30937
$30937data = foreach($d in $dotnet){
    get-content $d | where{$_ -like '*NetFx40_LegacySecurityPolicy*' } | select @{n = "Path"; e = {$d}}, @{n = "Match"; e = {$_}}
}

stig_object -vulnid "V-30937" -status "Finding" -data $30937data -depth 2

#30968
$load = $(foreach($d in $dotnet){
    get-content $d | where{$_ -like '*loadfromremotesources*' } | select @{n = "Path"; e = {$d}}, @{n = "Match"; e = {$_}}
})

if($load){
    $load | ft -AutoSize
}else{
    Write-Host "Not A Finding"
}

stig_object -vulnid "V-30968" -status $30968stat

#30972
foreach($d in $dotnet){
    $found = get-content $d | where{$_ -like '*defaultProxy*' } | select @{n = "Path"; e = {$d}}, @{n = "Match"; e = {$_}}

    if($found){
        Write-Host ""
        $d | ft -AutoSize
        Write-Host ""
        $gc = get-content $d | Select-String -SimpleMatch "defaultProxy" -Context 0,3
        Write-Host $gc
    }
}

stig_object -vulnid "V-30972" -status $30972stat

#32025
$chanref = $(foreach($d in $dotnet){
    get-content $d | where{$_ -like '*channel ref=*' } | select @{n = "Path"; e = {$d}}, @{n = "Match"; e = {$_}}
})

if($chanref){
    $chanref | ft -AutoSize
}else{
    Write-Host "Finding"
}

stig_object -vulnid "V-32025" -status $32025stat
