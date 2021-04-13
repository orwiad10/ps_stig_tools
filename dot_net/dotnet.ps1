#V2R1?

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

$dotnet     = & cmd.exe /c "dir c:\ /A-D /b /s" 4>$null 3>$null 2>$null
$dotnet     = $dotnet | where{$_ -like "*machine.config" -or $_ -like "*exe.config"}

$caspol     = gci "C:\Windows\Microsoft.NET\Framework64" -Recurse | where{$_.name -eq "caspol.exe"} | select fullname
$cassorted  = ($caspol.fullname | %{[version]$_.split("\")[-2].replace("v","")} | sort -Descending)[0].ToString()
$newestdnet = ($caspol | where{$_.fullname -like "*$cassorted*"}).fullname

if($dotnet -eq $null){
    throw "GCI Failed"
}

#7055
$StrN     = Test-Path HKLM:\SOFTWARE\Microsoft\strongname\verification
if($StrN -eq $false){
    $7055stat = "NotAFinding"
    $7055data = "Path not found"
}else{
    $7055stat = "Open"
    $7055data = "Path found"
}

stig_object -vulnid "V-7055" -status $7055stat -data $7055data

#7063
$check = &$newestdnet -m -lg | select-string -pattern "1.6"

if($check -eq $null -or $check -eq ""){
    $7063data = "No Data Found"
}else{
    $7063data = $check | select line
}

stig_object -vulnid "V-7063" -status Open -data $7063data

#7067
$check1 = &$newestdnet -all -lg | select-string -pattern "strongname"

if($check1 -eq $null -or $check1 -eq "") {
    $7067data = $null
}else{
    $7067data = $check1 | select line
}

stig_object -vulnid "V-7067" -status "Open" -data $7067data

#7070
$chan = $(foreach($d in $dotnet){
    get-content $d | where{$_ -like '*channel ref=*' } | select @{n = "Path"; e = {$d}}, @{n = "Match"; e = {$_}}
})

if($chan){
    $7070data = $chan
}else{
    $7070data = "No Data Found"
}

stig_object -vulnid "V-7070" -status "Open" -data $7070data

#18395
stig_object -vulnid "V-18395" -status "Open" -data ((Get-ChildItem C:\windows\Microsoft.NET\F* -Recurse -force | where{$_.Name -eq "Mscorlib.dll"} ).VersionInfo | where{$_.internalname -eq "Mscorlib.dll"} | select filename, productversion)

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

stig_object -vulnid "V-30935" -status "Open" -data $30935data

#30937
$30937data = foreach($d in $dotnet){
    get-content $d | where{$_ -like '*NetFx40_LegacySecurityPolicy*' } | select @{n = "Path"; e = {$d}}, @{n = "Match"; e = {$_}}
}

stig_object -vulnid "V-30937" -status "Open" -data $30937data
#30968
$load = $(foreach($d in $dotnet){
    get-content $d | where{$_ -like '*loadfromremotesources*' } | select @{n = "Path"; e = {$d}}, @{n = "Match"; e = {$_}}
})

if($load){
    $30968data = $load | ft -AutoSize
    $30968stat = "Open"
}else{
    $30968data = "No Data Found"
    $30968stat = "NotAFinding"
}

stig_object -vulnid "V-30968" -status $30968stat -data $30968data

#30972
$30972data = $(foreach($d in $dotnet){
    $found = get-content $d | where{$_ -like '*defaultProxy*' } | select @{n = "Path"; e = {$d}}, @{n = "Match"; e = {$_}}

    if($found){
        [pscustomobject]@{
            path    = $d
            content = get-content $d | Select-String -SimpleMatch "defaultProxy" -Context 0,3
        }
    }
})

stig_object -vulnid "V-30972" -status Open -data $30972data

#32025
$chanref = $(foreach($d in $dotnet){
    get-content $d | where{$_ -like '*channel ref=*' } | select @{n = "Path"; e = {$d}}, @{n = "Match"; e = {$_}}
})

if($chanref){
    $32025data = $chanref
}else{
    $32025data = "No Data Found"
}

stig_object -vulnid "V-32025" -status Open -data $32025data