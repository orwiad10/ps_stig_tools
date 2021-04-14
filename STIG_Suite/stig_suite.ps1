#version 1
param(
    [parameter(Mandatory=$true)]
    [string]$targetcomputer
)

#This script creates a menu system to make it easier for those less knowledgeable with powershell, i.e., you can task juniors to do STIGs with little worry.
#this is not a very generalized script so many environment specific things may need to change for this to work in your env.

#it uses the general work flow of:

#download and prep stigs in to checklists and benchmarks in to the xmls files.
#preps a system for remote access
#remotly installs oscap and runs scap scans on MAC 2 sensitive, (if you need a different profile, this hasnt been parameterized yet so go and change it in that function)
#runs non-scap non-administrative checks on remote systems using OS/App dependant powershell scripts.
#combines all checks and adds them to a CKL, blank or partially complete. (uses a fairly complex true table to figure out which comment status pair wins between the 3 sources csv, ckl and live results)

#dependancies for this script are:

#the stigs and benchmarks which can be downloaded from within the script.
#oscap installer, maybe ill add a downloader for this as well someday
#manual powershell scripts, (these need to be updated and maintained to match the up-to-dateness of the ckl / benchmarks)
#csv exports from stig veiwer with the headers: "Vuln ID","Status","Comments", (also needs to be same version as ckl being used.)
#Ideally this csv will be what the end state of the stig should look like as approved by IA/Cyber, to include comments.


#openfile function
Function Open-File {   
    param($initialDirectory,$filter,$description)
    
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null

    $OpenFileDialog                  = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.Title            = $description
    $OpenFileDialog.initialDirectory = $initialDirectory
    $OpenFileDialog.filter           = $filter
    $OpenFileDialog.Multiselect      = $false
    $OpenFileDialog.ShowDialog() | Out-Null
    $OpenFileDialog.filenames
}

Function Get-Folder {
    param($description)
    
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null

    $foldername              = New-Object System.Windows.Forms.FolderBrowserDialog
    $foldername.Description  = $description
    $foldername.rootfolder   = "MyComputer"
    $foldername.SelectedPath = $env:USERPROFILE + "\desktop"

    if($foldername.ShowDialog() -eq "OK"){
        $folder += $foldername.SelectedPath
    }

    return $folder
}

function setup_menu {
    [pscustomobject]@{
        1  = "Download New STIGs"
        2  = "Download New Benchmarks"
        3  = "Create Empty CKL from STIG.zip"
        4  = "Enable Remote RPC Calls"
        5  = "Reboot Target"
        6  = "Enable WinRm"
        7  = "Copy Agent"
        8  = "Install Oscap"
        9  = "Run Oscap"
        10 = "Run Manuals"
        11 = "Add All Findings To Empty CheckList"
        12 = "Quit"
    } | format-list
}

#switch user input for menu functions
function setupinput {
    param($targetcomputer,$credential)

    switch(read-host -Prompt "Enter A Number"){
        
        1       {download_new_stigs}

        2       {download_new_benchmarks}

        3       {
                    $zippath = (Open-File -filter "ZIP (CheckList) (*.zip)| *.zip" -initialDirectory "$env:USERPROFILE\desktop" -description "Select The STIG ZIP To Convert To CKL")
                    $outpath = Get-Folder -description "Select Destination For STIG CKL"
                    empty_ckl_from_zip -XccdfPath $zippath -OutputPath ($outpath + "\" + $zippath.split("\")[-1].replace(".zip",".ckl"))
                }
        
        4       {try{enable_remote_rpc -targetcomputer $targetcomputer -credential $credential}catch{}}

        5       {
                    (gwmi win32_operatingsystem -ComputerName $targetcomputer -credential $credential).Win32Shutdown(6) | out-null
                    while((Test-Connection -ComputerName $targetcomputer -Count 1 -Quiet) -ne $true){Start-Sleep -Seconds 3}
                }

        6       {remote_winrm_enable -targetcomputer $targetcomputer -credential $credential}

        7       {copy_package -targetcomputer $targetcomputer -credential $credential}

        8       {install_oscap -targetcomputer $targetcomputer -credential $credential}

        9       {Run_oscap -targetcomputer $targetcomputer -credential $credential}

        10      {run_manuals -targetcomputer $targetcomputer -credential $credential}

        11      {findings_to_ckl}

        12      {$global:quit = $true}

        default {continue}
    }
}

function download_new_stigs {

    #get the url to the compilation of stigs
    $res     = Invoke-WebRequest -Uri https://public.cyber.mil/stigs/compilations/
    $stigdl  = $res.Links.href | where{$_ -like "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/*.zip"}
    $zipname = $stigdl.split("/")[-1]

    $zipfolder = Get-Folder -description "Select Folder For STIG Downloads"

    #download the zip 
    Invoke-WebRequest -Uri $stigdl -OutFile $zipfolder\$zipname

    $unpackfolder = Get-Folder -description "Select Folder For STIG To Be Unzipped To"

    #create the dir and expand the archive
    mkdir $unpackfolder -Force -Confirm:$false | Out-Null
    Expand-Archive -Path $zipfolder\$zipname -DestinationPath $unpackfolder

    #cleanup
    Remove-Item -Path $zipfolder -Force -Recurse -Confirm:$false | Out-Null
}

function download_new_benchmarks {

    #get list of all benchmark links
    $res        = Invoke-WebRequest -Uri https://public.cyber.mil/stigs/scap/
    $benchmarks = $res.Links.href | where{$_ -like "*Benchmark.zip"}

    #create the dir for the files
    $benchdlpath = Get-Folder -description "Select Folder To Download Benchmarks To"
    mkdir $benchdlpath -Force -Confirm:$false | Out-Null

    #download async to make things a little faster
    $asyncdl = foreach($b in $benchmarks){ 

        $zipname = $b.split("/")[-1]

        $wc = New-Object System.Net.WebClient

        write-output $wc.DownloadFileTaskAsync($b, "$benchdlpath\$zipname")
    }

    #wait for iscompleted to not contain false, all are complete.
    while($asyncdl.IsCompleted.contains($false)){
        Start-Sleep -Seconds 5
    }

    #make dir for unpacking
    $benchunpack = Get-Folder -description "Select Folder To Unpack Benchmarks To"
    mkdir $benchunpack -Force -Confirm:$false | Out-Null

    #get all bench zips
    $benchpaths = (Get-ChildItem $benchdlpath).FullName

    #unpack all zips to xmls
    foreach($b in $benchpaths){
        Expand-Archive -Path $b -DestinationPath $benchunpack
    }

    #cleanup
    Remove-Item $benchdlpath -Force -Recurse -Confirm:$false | Out-Null
}

function empty_ckl_from_zip {
    #taken and modified from powerstig.
    param(

        [Parameter(Mandatory = $true)]
        [string]
        $XccdfPath,

        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]
        $OutputPath
    )

    if(-not (Test-Path -Path $OutputPath.DirectoryName)){
        throw "$($OutputPath.DirectoryName) is not a valid directory. Please provide a valid directory."
    }

    if($OutputPath.Extension -ne '.ckl'){
        throw "$($OutputPath.FullName) is not a valid checklist extension. Please provide a full valid path ending in .ckl"
    }

    function Get-VulnerabilityList{
    
        [CmdletBinding()]
        [OutputType([xml])]
    
        param(
            [Parameter()]
            [psobject]
            $XccdfBenchmark
        )

        [System.Collections.ArrayList] $vulnerabilityList = @()

        foreach($vulnerability in $XccdfBenchmark.Group){
        
            [xml]$vulnerabiltyDiscussionElement = "<discussionroot>$($vulnerability.Rule.description)</discussionroot>"

            [void]$vulnerabilityList.Add(
                @(
                    [PSCustomObject]@{ Name = 'Vuln_Num'                   ; Value = $vulnerability.id },
                    [PSCustomObject]@{ Name = 'Severity'                   ; Value = $vulnerability.Rule.severity},
                    [PSCustomObject]@{ Name = 'Group_Title'                ; Value = $vulnerability.title},
                    [PSCustomObject]@{ Name = 'Rule_ID'                    ; Value = $vulnerability.Rule.id},
                    [PSCustomObject]@{ Name = 'Rule_Ver'                   ; Value = $vulnerability.Rule.version},
                    [PSCustomObject]@{ Name = 'Rule_Title'                 ; Value = $vulnerability.Rule.title},
                    [PSCustomObject]@{ Name = 'Vuln_Discuss'               ; Value = $vulnerabiltyDiscussionElement.discussionroot.VulnDiscussion},
                    [PSCustomObject]@{ Name = 'IA_Controls'                ; Value = $vulnerabiltyDiscussionElement.discussionroot.IAControls},
                    [PSCustomObject]@{ Name = 'Check_Content'              ; Value = $vulnerability.Rule.check.'check-content'},
                    [PSCustomObject]@{ Name = 'Fix_Text'                   ; Value = $vulnerability.Rule.fixtext.InnerText},
                    [PSCustomObject]@{ Name = 'False_Positives'            ; Value = $vulnerabiltyDiscussionElement.discussionroot.FalsePositives},
                    [PSCustomObject]@{ Name = 'False_Negatives'            ; Value = $vulnerabiltyDiscussionElement.discussionroot.FalseNegatives},
                    [PSCustomObject]@{ Name = 'Documentable'               ; Value = $vulnerabiltyDiscussionElement.discussionroot.Documentable},
                    [PSCustomObject]@{ Name = 'Mitigations'                ; Value = $vulnerabiltyDiscussionElement.discussionroot.Mitigations},
                    [PSCustomObject]@{ Name = 'Potential_Impact'           ; Value = $vulnerabiltyDiscussionElement.discussionroot.PotentialImpacts},
                    [PSCustomObject]@{ Name = 'Third_Party_Tools'          ; Value = $vulnerabiltyDiscussionElement.discussionroot.ThirdPartyTools},
                    [PSCustomObject]@{ Name = 'Mitigation_Control'         ; Value = $vulnerabiltyDiscussionElement.discussionroot.MitigationControl},
                    [PSCustomObject]@{ Name = 'Responsibility'             ; Value = $vulnerabiltyDiscussionElement.discussionroot.Responsibility},
                    [PSCustomObject]@{ Name = 'Security_Override_Guidance' ; Value = $vulnerabiltyDiscussionElement.discussionroot.SeverityOverrideGuidance},
                    [PSCustomObject]@{ Name = 'Check_Content_Ref'          ; Value = $vulnerability.Rule.check.'check-content-ref'.href },
                    [PSCustomObject]@{ Name = 'Weight'                     ; Value = $vulnerability.Rule.Weight},
                    [PSCustomObject]@{ Name = 'Class'                      ; Value = 'Unclass'},
                    [PSCustomObject]@{ Name = 'STIGRef'                    ; Value = "$($XccdfBenchmark.title) :: $($XccdfBenchmark.'plain-text'.InnerText)"},
                    [PSCustomObject]@{ Name = 'TargetKey'                  ; Value = $vulnerability.Rule.reference.identifier}

                    # Some Stigs have multiple Control Correlation Identifiers (CCI)
                    $(
                        # Extract only the cci entries
                        $CCIREFList = $vulnerability.Rule.ident | Where-Object {$PSItem.system -eq 'http://iase.disa.mil/cci'} | Select-Object 'InnerText' -ExpandProperty 'InnerText'

                        foreach ($CCIREF in $CCIREFList){
                            [PSCustomObject]@{ Name = 'CCI_REF'; Value = $CCIREF}
                        }
                    )
                )
            )
        }

        return $vulnerabilityList
    }

    function Get-StigXccdfBenchmarkContent{
        [CmdletBinding()]
        [OutputType([xml])]
        param(
            [Parameter(Mandatory = $true)]
            [string]
            $Path
        )

        if(-not(Test-Path -Path $Path)){
            Throw "The file $Path was not found"
        }

        if($Path -like "*.zip"){
            [xml] $xccdfXmlContent = Get-StigContentFromZip -Path $Path
        }else{
            [xml] $xccdfXmlContent = Get-Content -Path $Path -Encoding UTF8
        }

        $xccdfXmlContent.Benchmark
    }

    function Get-StigContentFromZip{
        [CmdletBinding()]
        [OutputType([xml])]
    
        param(
            [Parameter(Mandatory = $true)]
            [string]
            $Path
        )

        # Create a unique path in the users temp directory to expand the files to.
        $zipDestinationPath = "$((Split-Path -Path $Path -Leaf) -replace '.zip','').$((Get-Date).Ticks)"
        Expand-Archive -LiteralPath $Path -DestinationPath $zipDestinationPath
    
        # Get the full path to the extracted xccdf file.
        $getChildItem = @{
            Path    = $zipDestinationPath
            Filter  = "*Manual-xccdf.xml"
            Recurse = $true
        }

        $xccdfPath = (Get-ChildItem @getChildItem).fullName
    
        # Get the xccdf content before removing the content from disk.
        $xccdfContent = Get-Content -Path $xccdfPath
    
        # Cleanup to temp folder
        Remove-Item $zipDestinationPath -Recurse -Force

        $xccdfContent
    }

    function New-StigCheckList{
        [CmdletBinding()]
        [OutputType([xml])]
    
        param(

            [Parameter(Mandatory = $true)]
            [string]
            $XccdfPath,

            [Parameter(Mandatory = $true)]
            [System.IO.FileInfo]
            $OutputPath
        )

        if(-not (Test-Path -Path $OutputPath.DirectoryName)){
            throw "$($OutputPath.DirectoryName) is not a valid directory. Please provide a valid directory."
        }

        if($OutputPath.Extension -ne '.ckl'){
            throw "$($OutputPath.FullName) is not a valid checklist extension. Please provide a full valid path ending in .ckl"
        }

        $xmlWriterSettings              = [System.Xml.XmlWriterSettings]::new()
        $xmlWriterSettings.Indent       = $true
        $xmlWriterSettings.IndentChars  = "`t"
        $xmlWriterSettings.NewLineChars = "`n"
        $writer                         = [System.Xml.XmlWriter]::Create($OutputPath.FullName, $xmlWriterSettings)

        $writer.WriteStartElement('CHECKLIST')

        #region ASSET

        $writer.WriteStartElement("ASSET")

        $assetElements = [ordered]@{
        
            'ROLE'            = 'None'
            'ASSET_TYPE'      = 'Computing'
            'HOST_NAME'       = ''
            'HOST_IP'         = ''
            'HOST_MAC'        = ''
            'HOST_GUID'       = ''
            'HOST_FQDN'       = ''
            'TECH_AREA'       = ''
            'TARGET_KEY'      = '2350'
            'WEB_OR_DATABASE' = 'false'
            'WEB_DB_SITE'     = ''
            'WEB_DB_INSTANCE' = ''
        }

        foreach($assetElement in $assetElements.GetEnumerator()){
        
            $writer.WriteStartElement($assetElement.name)
            $writer.WriteString($assetElement.value)
            $writer.WriteEndElement()
        }

        $writer.WriteEndElement(<#ASSET#>)

        #endregion ASSET

        $writer.WriteStartElement("STIGS")
        $writer.WriteStartElement("iSTIG")

        #region STIGS/iSTIG/STIG_INFO

        $writer.WriteStartElement("STIG_INFO")

        $xccdfBenchmarkContent = Get-StigXccdfBenchmarkContent -Path $xccdfPath

        $stigInfoElements = [ordered]@{
        
            'version'        = $xccdfBenchmarkContent.version
            'classification' = 'UNCLASSIFIED'
            'customname'     = ''
            'stigid'         = $xccdfBenchmarkContent.id
            'description'    = $xccdfBenchmarkContent.description
            'filename'       = Split-Path -Path $xccdfPath -Leaf
            'releaseinfo'    = $xccdfBenchmarkContent.'plain-text'.InnerText
            'title'          = $xccdfBenchmarkContent.title
            'uuid'           = (New-Guid).Guid
            'notice'         = $xccdfBenchmarkContent.notice.InnerText
            'source'         = $xccdfBenchmarkContent.reference.source
        }

        foreach ($StigInfoElement in $stigInfoElements.GetEnumerator()){
        
            $writer.WriteStartElement("SI_DATA")
            $writer.WriteStartElement('SID_NAME')
            $writer.WriteString($StigInfoElement.name)
            $writer.WriteEndElement(<#SID_NAME#>)
            $writer.WriteStartElement('SID_DATA')
            $writer.WriteString($StigInfoElement.value)
            $writer.WriteEndElement(<#SID_DATA#>)
            $writer.WriteEndElement(<#SI_DATA#>)
        }

        $writer.WriteEndElement(<#STIG_INFO#>)

        #endregion STIGS/iSTIG/STIG_INFO

        #region STIGS/iSTIG/VULN[]

        foreach($vulnerability in (Get-VulnerabilityList -XccdfBenchmark $xccdfBenchmarkContent)){
        
            $writer.WriteStartElement("VULN")

            foreach ($attribute in $vulnerability.GetEnumerator()){
            
                $status         = $null
                $comments       = $null
                $findingdetails = $null

                if ($attribute.Name -eq 'Vuln_Num'){
                    $vid = $attribute.Value
                }

                $writer.WriteStartElement("STIG_DATA")
                $writer.WriteStartElement("VULN_ATTRIBUTE")
                $writer.WriteString($attribute.Name)
                $writer.WriteEndElement(<#VULN_ATTRIBUTE#>)
                $writer.WriteStartElement("ATTRIBUTE_DATA")
                $writer.WriteString($attribute.Value)
                $writer.WriteEndElement(<#ATTRIBUTE_DATA#>)
                $writer.WriteEndElement(<#STIG_DATA#>)
            }

            $statusMap = @{
                NotReviewed   = 'Not_Reviewed'
                Open          = 'Open'
                NotAFinding   = 'NotAFinding'
                NotApplicable = 'Not_Applicable'
            }

            $status = $statusMap['NotReviewed']

            $writer.WriteStartElement("STATUS")
            $writer.WriteString($status)
            $writer.WriteEndElement(<#STATUS#>)
            $writer.WriteStartElement("FINDING_DETAILS")
            $writer.WriteString($findingdetails)
            $writer.WriteEndElement(<#FINDING_DETAILS#>)
            $writer.WriteStartElement("COMMENTS")
            $writer.WriteString($comments)
            $writer.WriteEndElement(<#COMMENTS#>)
            $writer.WriteStartElement("SEVERITY_OVERRIDE")
            $writer.WriteString('')
            $writer.WriteEndElement(<#SEVERITY_OVERRIDE#>)
            $writer.WriteStartElement("SEVERITY_JUSTIFICATION")
            $writer.WriteString('')
            $writer.WriteEndElement(<#SEVERITY_JUSTIFICATION#>)
            $writer.WriteEndElement(<#VULN#>)
        }

        #endregion STIGS/iSTIG/VULN[]

        $writer.WriteEndElement(<#iSTIG#>)
        $writer.WriteEndElement(<#STIGS#>)
        $writer.WriteEndElement(<#CHECKLIST#>)
        $writer.Flush()
        $writer.Close()
    }

    New-StigCheckList -XccdfPath $XccdfPath -OutputPath $OutputPath
}

function enable_remote_rpc {
    param($targetcomputer,$credential)

    #cim args for registry
    $arguments = @{
        sSubKeyName = 'SYSTEM\CurrentControlSet\Control\Terminal Server'
        sValueName  = "AllowRemoteRPC"
        uValue      = [uint32]1
    }

    #use cim so we can specify alternate creds
    $session = New-CimSession -ComputerName $targetcomputer -Credential $credential
    Invoke-CimMethod -ClassName stdRegProv -Namespace Root/default -MethodName SetDWORDValue -Arguments $arguments -CimSession $session
    Remove-CimSession -CimSession $session
}

function remote_winrm_enable {
    param($targetcomputer,$credential)

    #pretty sketchy way to remotley enable winrm
    $wmicenres = wmic /user:"$(($credential.UserName).Replace("domainname\",''))" /password:"$($credential.GetNetworkCredential().password)" /node:`'$targetcomputer`' process call create 'cmd winrm quickconfig -quiet' 4>$null 3>$null 2>$null

    #format returns
    $wmires = ($wmicenres | where{$_ -like "*ReturnValue*"}).replace("	","").replace(";","")

    #check return and remotely start the service.
    if($wmires -eq "ReturnValue = 0"){
        
        $serviceres = (gwmi win32_service -ComputerName $targetcomputer -Credential $credential | where{$_.name -like "winrm"}).startservice()

        if($serviceres.ReturnValue -eq 0 -or $serviceres.ReturnValue -eq 10){
        }else{
            throw "Couldnt Start WinRm Service Remotley"
        }

    }else{
        throw "Couldnt Remotley Set Up WinRm"
    }
}

function copy_package {
    param($targetcomputer,$credential)
    
    #path to openscap installer
    $installer = Open-File -initialDirectory "$env:USERPROFILE\desktop" -filter "MSI (Microsoft Installer) (*.msi)| *.msi" -description "Select OSCAP Installer"

    #new psdrive to admin path to copy installer
    New-PSDrive -Name Y -PSProvider filesystem -Root "\\$targetcomputer\c$" -Credential $credential | Out-Null
    Copy-Item "$installer" -Destination Y:\ -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
    Remove-PSDrive -Name Y | Out-Null
}

function install_oscap {
    param($targetcomputer,$credential)

    #invoke command to remote install scap
    Invoke-Command -ComputerName $targetcomputer -Credential $credential -ScriptBlock {

        #disable OAP via reg key
        $pass        = "mcafeepassword"
        $wmi         = [wmiclass]"\\$env:computername\ROOT\DEFAULT:StdRegProv"
        $HKLM        = 2147483650
        $sSubKeyName = 'software\WOW6432Node\McAfee\SystemCore\VSCore\On Access Scanner\BehaviourBlocking'
        $valname     = 'APEnabled'
        $off         = 0
        $on          = 1

        #disable hips
        Start-Process "C:\Program Files\McAfee\Host Intrusion Prevention\ClientControl.exe" -argumentlist "/stop $pass hipmgmt" -NoNewWindow -ErrorAction SilentlyContinue | Out-Null
        $wmi.SetDWORDValue($hklm,$ssubkeyname,$valname,$off) | out-null
        
        #join string and call installer
        $inst_str = -join("/i ", '"',"c:\OpenSCAP-1.3.0-win32.msi",'" ', "/qn")
        Start-Process 'msiexec.exe' -ArgumentList $inst_str -NoNewWindow -wait -ErrorAction SilentlyContinue | Out-Null

        #enable
        Start-Process "C:\Program Files\McAfee\Host Intrusion Prevention\ClientControl.exe" -argumentlist "/start $pass hipmgmt" -NoNewWindow -ErrorAction SilentlyContinue | Out-Null
        $wmi.SetDWORDValue($hklm,$ssubkeyname,$valname,$on) | out-null

        #clean up
        Remove-Item "c:\OpenSCAP-1.3.0-win32.msi" -Force -Confirm:$false | Out-Null
    }
}

function run_oscap {
    param($targetcomputer,$credential)
    
        function benchmark_menu {
        [pscustomobject]@{
            1 = "Windows 10"
            2 = "Server 2016"
            3 = "Adobe"
            4 = "Chrome"
            5 = "DOTNET"
            6 = "IE"
        } | format-list
    }

    #switch user input for menu functions
    function benchmark_input {
        switch(read-host -Prompt "Enter A Number"){
            1 {"windows_10"}
            2 {"server_2016"}
            3 {"adobe"}
            4 {"Chrome"}
            5 {"DOTNET"}
            6 {"IE11"}
        }
    }

    cls
    benchmark_menu
    $benchmark = benchmark_input

    #path to scap benchmarks
    $benchpaths      = Get-ChildItem (Get-Folder -description "Select Folder That Contains Benchmark XML Files") | select name, fullname
    $benchmarkfound  = ($benchpaths | where{$_.name -like "*$benchmark*"}).fullname

    #psrive to copy benchmarks to admin path
    New-PSDrive -Name Y -PSProvider filesystem -Root "\\$targetcomputer\c$" -Credential $credential | Out-Null
    Copy-Item "$benchmarkfound" -Destination Y:\ -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
    Remove-PSDrive -Name Y | Out-Null

    #benchmark file path
    $benchmark = "c:\$($benchmarkfound.Split("\")[-1])"
    
    $cleanres = Invoke-Command -ComputerName $targetcomputer -Credential $credential -ArgumentList $benchmark -ScriptBlock {
        param($benchmark)

        #call the scap exe and specify profile and benchmark 
        $scapres = & "C:\Program Files (x86)\OpenSCAP 1.3.0\oscap.exe" xccdf eval --profile MAC-2_Sensitive --progress $benchmark 4>$null 3>$null 2>$null

        #clean up before returning results
        foreach($s in $scapres){
            [pscustomobject]@{
                Vulnid = [regex]::Match($s,'\d+')
                Result = $s.split(":")[1]
            }
        }

        #cleanup
        remove-item -Path $benchmark -Force -Confirm:$false | out-null
    }

    #serialize results and convert status. append a V- so it matched the ckl xml
    $global:serializedres = $(foreach($c in $cleanres){
        
        [pscustomobject]@{
            VulnID = "V-" + [string]$c.vulnid
            Status = switch($c.result){
                "unknown" {'Open'}
                "pass"    {'NotAFinding'}
                "fail"    {'Open'}
            }
            Data   = "Compliance verified by SCAP"
        }
    })
}

function run_manuals {
    param($targetcomputer,$credential)
    
    function manual_menu {
        [pscustomobject]@{
            1 = "Windows 10"
            2 = "Server 2016"
            3 = "DOTNET"
            4 = "IE"
        } | format-list
    }

    #switch user input for menu functions
    function manual_input {
        
        $path = Get-Folder -description "Select Folder That Contains The Manual Check Scripts"
        
        switch(read-host -Prompt "Enter A Number"){
            1       {"$path\10\10.ps1"}
            2       {"$path\2016\2016.ps1"}
            3       {"$path\dot_net\dotnet.ps1"}
            4       {"$path\IE\IE.ps1"}
            default {$stigquit = $true}
        }
    }

    cls
    manual_menu
    $manualfile = manual_input

    #get the manuals script raw
    $gc_sb = Get-Content $manualfile -Raw

    #convert the script to a script block
    $sb = [System.Management.Automation.ScriptBlock]::Create($gc_sb)

    #run the manual checks and return the results.
    $global:manualres = Invoke-Command -ComputerName $targetcomputer -Credential $credential -ScriptBlock $sb | select vulnid, status, data
}

function findings_to_ckl {
    
    #get checklist. empty or partial is ok
    $cklpath = (Open-File -filter "CKL (CheckList) (*.ckl)| *.ckl" -initialDirectory "$env:USERPROFILE\desktop" -description "Select CKL To Add Comments To")
    $csv     = import-csv (Open-File -filter "CSV (Comma Delimited) (*.csv)| *.csv" -initialDirectory "$env:USERPROFILE\desktop" -description "Select Comments Export CSV")

    #combine manuals and scap
    $allres  = $global:manualres + $global:serializedres
    
    #import ckl
    $ckl     = Get-Content $cklpath

    #you can fill the host data, must be up and connectable.
    if(((Read-Host -Prompt "'Y' or 'N' - Generate Host Data For $targetcomputer") -eq "y")){
        
        $hostinfo = [pscustomobject]@{
            name        = $targetcomputer
            DNSHostName = $targetcomputer + "." + $env:USERDNSDOMAIN
            IPv4Address = (Test-Connection $targetcomputer -Count 1).IPV4Address.ipaddresstostring
            MAC         = $(
                #turn on winrm so we can invoke.
                (gwmi win32_service -ComputerName $targetcomputer -Credential $credential | where{$_.name -like "winrm"}).startservice() | out-null
                Invoke-Command $targetcomputer -credential $credential -scriptblock {
                    #might need to be a little more advance here if work on multi adapter systems.
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
        
        #find and replace host data based off of static indexes, this should be the same in every ckl, but i havent tested most of them
        if($hostinfo){
            [int]$type = Read-Host -Prompt "Enter type number"

            $ckl[4] = $ckl[4] -Replace ">.*</",">$($list[$type])</"
            $ckl[6] = $ckl[6] -Replace ">.*/",">$($hostinfo.name)</"
            $ckl[7] = $ckl[7] -Replace ">.*</",">$($hostinfo.IPv4Address)</"
            $ckl[8] = $ckl[8] -Replace ">.*</",">$($hostinfo.MAC)</"
            $ckl[9] = $ckl[9] -Replace ">.*</",">$($hostinfo.DNSHostName)</"
        }else{
            Write-Host "Fill Out Host Data For $targetcomputer"
        }
    }else{
        Write-Host "Couldnt Generate Host Data for $targetcomputer"
    }

    #foreach check in the CSV maybe i need to change this to each vuln in the ckl?
    foreach($c in $csv){
        
        #check if the the ckl and live results contains the csv checks
        $cklcontains = if(([regex]::Match($ckl,"\s+<ATTRIBUTE_DATA>$($c."vuln id")</ATTRIBUTE_DATA>")).value){
            4
        }else{
            0
        }

        $rescontains = if($allres.vulnid.contains($c."vuln id")){
            1
        }else{
            0
        }

        #checklist is 4, csv is 2 so we always have that since our loop is the csv and the live results is 1
        $containssum = $cklcontains + $rescontains + 2

        #mini log of found deltas during the jive check
        $deltas = @()

        #switch on the contains sum so we can prioritize the data accordingly
        switch($containssum){
                    
                    #the vulnid was found no where. this is impossible.
            0       {break}

                    #the vulnid was found only in live results. this is impossible.
            1       {break}

                    #the vulnid was found only in the csv, the csv is probably old.
            2       {             
                        $deltas += [pscustomobject]@{
                            location = "csv"
                            vulnid   = $c."vuln id"
                        }
                        break
                    }

                    #the vulnid is missing from the CKL, the CKL is probably old.
            3       {   
                        $deltas += [pscustomobject]@{
                            location = "csv,res"
                            vulnid   = $c."vuln id"
                        }
                        break
                    }

                    #the vulnid was found only in the CKL this is impossible.
            4       {break}

                    #the vulnid missing from the csv this is impossible.
            5       {break}

                    #the vulnid missing from the live results, the bechmark or manuals script is old.
            6       {    
                        $deltas += [pscustomobject]@{
                            location = "csv,ckl"
                            vulnid   = $c."vuln id"
                        }
                        break
                    }

                    #the vulnid was found in all 3, its time to party.
            7       {
                        #find the vul id from the csv in the check list
                        $find = ([regex]::Match($ckl,"\s+<ATTRIBUTE_DATA>$($c."vuln id")</ATTRIBUTE_DATA>")).value

                        #result obj
                        $r = $allres | where{$_.vulnid -eq $c."vuln id"}

                        #get its index
                        if($find){
                            
                            $p = 0
                            
                            $index = foreach($el in $ckl){ 
                                if($el -eq $find.Substring(1,$find.length - 1)){
                                    $p
                                    break
                                }
                                ++$p
                            }
                        }else{
                            #ckl does not contain vulnid
                            break
                        }

                        #based off of the vuln id index add the bare minimum of 92 to the increment so we avoid unneeded loops where we know we wont find anything, then start looping again till we find the status.
                        for($i = ($index + 92); $i++){

                            #if we match on status
                            if([regex]::Match($ckl[$i],"\s+<STATUS>.+</STATUS>").value){
                                
                                #get the status value
                                $checkstatus = ([regex]::Match(([regex]::Match($ckl[$i],"\s+<STATUS>.+</STATUS>").value),">.+<").value).replace("<","").replace(">","")

                                #status bitmap
                                $resbit = switch($r.status){
                                    "Not_Reviewed"   {1}
                                    "Not_Applicable" {2}
                                    "NotAFinding"    {4}
                                    "Open"           {8}
                                }

                                $csbit = switch($checkstatus){
                                    "Not_Reviewed"   {16}
                                    "Not_Applicable" {32}
                                    "NotAFinding"    {64}
                                    "Open"           {128}
                                }

                                $combit = $resbit + $csbit

                                #switch the combined value to make a choice of which status wins and where to get the comment from.
                                switch($combit){
                                    
                                    #first bit priority, mark as live result, add csv comments
                                    {@(18,20,34,66,68,130,132) -contains $combit}{
                                        $ckl[$i]     = $ckl[$i] -Replace ">.+</",">$($r.status)</"
                                        $ckl[$i + 2] = $ckl[$i + 2] -Replace ">.*</",">$($c.comments)</"
                                        break
                                    }

                                    #first bit priority, add live results data as comment, status should be open, convert data to json to bypass any wrapping or weirdness in the stig viewer.
                                    {@(24,40,72,136) -contains $combit}{
                                        $ckl[$i]     = $ckl[$i] -Replace ">.+</",">$($r.status)</"
                                        $ckl[$i + 2] = $ckl[$i + 2] -Replace ">.*</",">$($r.data | ConvertTo-Json -Depth 10)</"
                                        break
                                    }

                                    #second bit priority, let ckl status win, do not change comments, most of these should never happen becuase live results should never return as not reviewed, included for completeness.
                                    {@(33,36,65,128) -contains $combit}{
                                        $ckl[$i]     = $ckl[$i] -Replace ">.+</",">$($checkstatus)</"
                                        break
                                    }
                                    
                                    #once again, should never happen.
                                    {@(17) -contains $combit}{
                                        Break
                                    }
                                }

                                break
                            }
                        }
                        
                        break      
                    }

            default {break}
        }
    }

    #out the file and append the date, reset the value.
    $ckl | set-content $cklpath.replace(".ckl","-$(get-date -Format yyyyMMdd).ckl")
    $ckl = $null
    
    #for testing
    #$deltas | out-gridview
}

#add type
add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
        return true;
    }
}
"@

#make all protocols availible for invoke-webrequest
$AllProtocols                                       = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'
[System.Net.ServicePointManager]::SecurityProtocol  = $AllProtocols
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

$global:quit = $false

#creds for target system
$credential = get-credential -Message "Enter Appropriate Credentials For Target Computer"

#keep running the menu you until exit.
try{
    While($quit -eq $false) {
        cls
        setup_menu
        setupinput -targetcomputer $targetcomputer -credential $credential
    }
}catch{}
