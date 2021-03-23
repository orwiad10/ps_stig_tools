#46477
Write-Output ""
Write-Output "V-46477"

$sp = (get-itemproperty -path 'HKcu:\software\microsoft\windows\currentversion\wintrust\trust providers\software publishing' -name state -ErrorAction SilentlyContinue).state 

if ($sp -eq $null){
    write-output "No key found"
}else{
    "{0:x}" -f $sp
}

#46807
Write-Output ""
Write-Output "V-46807"

$fs = (get-itemproperty -path 'HKcu:\software\policies\microsoft\internet explorer\main' -name "use formsuggest" -ErrorAction SilentlyContinue)."use formsuggest"

if ($fs -eq $null){
    write-output "No key found"
}else{
    $fs
}

#46815
Write-Output ""
Write-Output "V-46815"

$fsp = (get-itemproperty -path 'HKcu:\software\policies\microsoft\internet explorer\main' -name "formsuggest passwords" -ErrorAction SilentlyContinue)."formsuggest passwords"

if ($fsp -eq $null){
    write-output "No key found"
}else{
    $fsp
}

#97527
Write-Output ""
Write-Output "V-97527"

$fsp = (get-itemproperty -path 'HKLM:\software\policies\microsoft\internet explorer\iedevtools' -name "disabled" -ErrorAction SilentlyContinue)."disabled"

if ($fsp -eq $null){
    write-output "No key found"
}else{
    $fsp
}
