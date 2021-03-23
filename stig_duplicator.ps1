#the idea of this script is that there is partner scripts that run each non-scap check against the target and the output of that script is reviewed.
#if the scap and the script output looks clean, then you can use this script to dupe.

#openfile function
Function Open-File($initialDirectory,$filter){   
    
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null

    $OpenFileDialog                  = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.initialDirectory = $initialDirectory
    $OpenFileDialog.filter           = $filter
    $OpenFileDialog.Multiselect      = $true
    $OpenFileDialog.ShowDialog() | Out-Null
    $OpenFileDialog.filenames
}

#get-pre-determined comments and any number of checklists for the same OS/Type
#csv format is (VulnID, Status, Comments) (vulnid = V-82139 status = "Not A Finding","Open", or "Not Applicable" and comment = what ever the comment is.)
#this csv is an export of an already completed by hand checklist. 
$stuff  = (Open-File -filter "CKL (CheckList) (*.ckl)| *.ckl" -initialDirectory ($env:USERPROFILE + "\desktop"))
$checks = import-csv (Open-File -filter "CSV (Comma delimited) (*.csv)| *.csv" -initialDirectory ($env:USERPROFILE + "\desktop"))

#foreach list
foreach($s in $stuff){
    
    #you can fill the host data, must be up and connectable.
    if(((Read-Host -Prompt "'Y' or 'N' - Generate Host Data For $s") -eq "y")){
        $name     = (Read-Host -Prompt "Enter Computer Name For Host Data:")
        $new      = Get-Content $s
        $hostinfo = [pscustomobject]@{
            name        = $name
            DNSHostName = $name + "." + $env:USERDNSDOMAIN
            IPv4Address = (Test-Connection $name -Count 1).IPV4Address.ipaddresstostring
            MAC         = $(
                #turn on winrm so we can invoke.
                (gwmi win32_service -ComputerName $name | where{$_.name -like "winrm"}).startservice() | out-null
                Invoke-Command $name -scriptblock {
                    #might need to be a little more advance here if working on multi adapter systems.
                    return [regex]::Match((getmac | where{$_ -notlike "*Media disconnected*"})[-1],'(([0-9A-F]{2}-){5}[0-9A-F]{2})').value
                }
            )
        }

        #type menu
        $list = [ordered]@{
            0 = "Workstation"
            1 = "Member Server"
            2 = "Domain Controller"
        }

        $list | ft
        
        #find and replace host data based off of static indexes
        if($hostinfo){
            [int]$type = Read-Host -Prompt "Enter type number"
            if($list[$type]){
                $new[4] = $new[4] -Replace ">.+</",">$($list[$type])</"
            }
            $new[6] = $new[6] -Replace ">.+</",">$($hostinfo.name)</"
            $new[7] = $new[7] -Replace ">.+</",">$($hostinfo.IPv4Address)</"
            $new[8] = $new[8] -Replace ">.+</",">$($hostinfo.MAC)</"
            $new[9] = $new[9] -Replace ">.+</",">$($hostinfo.DNSHostName)</"
        }else{
            Write-Host "Fill Out Host Data For $s"
        }
    }else{
        Write-Host "Couldnt Generate Host Data for $s"
    }
    
    #foreach check in the CSV
    foreach($c in $checks){

        #find the vul id from the csv in the check list
        $find = ([regex]::Match($new,"\s+<ATTRIBUTE_DATA>$($c.vulnid)</ATTRIBUTE_DATA>")).value

        #get its index
        if($find){
            $p = 0
            $index = foreach($el in $new){ 
                if($el -eq $find.Substring(1,$find.length-1)){
                    $p
                }
                ++$p
            }
        }else{
            continue
        }

        #based off of the vuln id index add the bare minimum of 92 to the increment so we avoid unneeded loops where we know we wont find anything, then start looping again till we find the status
        for($i = ($index + 92); $i++){

            #if we match on status
            if([regex]::Match($new[$i],"\s+<STATUS>.+</STATUS>").value){
            
                #get the status value
                $checkstatus = ([regex]::Match(([regex]::Match($new[$i],"\s+<STATUS>.+</STATUS>").value),">.+<").value).replace("<","").replace(">","")

                #break on open so we dont change it, meaning opens must be remediated by a human
                if($checkstatus -eq "Open"){
                    break
                }else{
                    #correlate the status to the XML schema value
                    $status = switch($c.status){
                        "Not A Finding"  {'NotAFinding'}
                        "Open"           {'Open'}
                        "Not Applicable" {'Not_Applicable'}
                        "Not Reviewed"   {'Not_Reviewed'}
                        default          {'Not_Reviewed'}
                    }

                    #replace status and comments then break. comment will always be a + 2
                    $comment     = $c.comments
                    $new[$i]     = $new[$i] -Replace ">.+</",">$status</"
                    $new[$i + 2] = $new[$i + 2] -Replace ">.+</",">$comment</"
                    break
                }
            }
        }
    }

    #out the file and append the date, reset the value.
    $new | set-content $s.replace(".ckl","-$(get-date -Format yyyyMMdd).ckl")
    $new = $null
}
