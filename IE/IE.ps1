#V1R19

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

$sids = ((Get-ChildItem 'HKU:\').name | Select-String -Pattern 'S-\d-(?:\d+-){4,14}\d+').Matches.Value

#46477
$sp = (get-itemproperty -path 'HKcu:\software\microsoft\windows\currentversion\wintrust\trust providers\software publishing' -name state -ErrorAction SilentlyContinue).state

if(("{0:x}" -f $sp) -eq "23c00"){
    stig_object -vulnid "V-46477" -status NotAFinding -data ("{0:x}" -f $sp)
}else{
    stig_object -vulnid "V-46477" -status Open -data $sp
}

#46807
$fs = $null

foreach($s in $sids){

    $fs = (get-itemproperty -path "HKU:\$s\software\policies\microsoft\internet explorer\main" -name "use formsuggest" -ErrorAction SilentlyContinue)."use formsuggest"

    if($fs -eq "no"){
        stig_object -vulnid "V-46807" -status NotAFinding -data $fs

        break
    }
}

if($fs -eq $null){
    stig_object -vulnid "V-46807" -status Open -data "No key found"
}

#46815
$fsp = $null

foreach($s in $sids){

    $fsp = (get-itemproperty -path "HKu:\$s\software\policies\microsoft\internet explorer\main" -name "formsuggest passwords" -ErrorAction SilentlyContinue)."formsuggest passwords"

    if($fsp -eq "no"){
        stig_object -vulnid "V-46815" -status NotAFinding -data $fsp

        break
    }
}

if($fs -eq $null){
    stig_object -vulnid "V-46815" -status Open -data "No key found"
}

#97527
$ied = (get-itemproperty -path 'HKLM:\software\policies\microsoft\internet explorer\iedevtools' -name "disabled" -ErrorAction SilentlyContinue)."disabled"

if($ied -eq 1){
    stig_object -vulnid "V-97527" -status NotAFinding -data $ied
}else{
    if($ied -eq $null){
        stig_object -vulnid "V-97527" -status Open -data "No key found"
    }else{
        stig_object -vulnid "V-97527" -status Open -data $ied
    }
}