<# 
.ABOUT
This PowerShell script was developed to gather system information from Windows systems to support BSW's audit requests. 
Information is collected and exported to be analyzed using these tools (e.g. Power BI).

All PowerShell commands used are read-only and do not make changes to the Operating System or Active Directory.
Please see Ref1.csv for the list of commands and justifications.

After successful execution of the script, a "C:\ADA" directory will be created with 2 files in the ADA directory.
There will also be another subdirectory with the hostname.
Please deliver only the .zip  and .md5 files to your ADA Auditors. You can then safely delete any output files in "C:\ADA".

.PREREQUISITES

Log in as a Windows administrator.

Microsoft PowerShell must be installed on the installation host before agent installation. The version required depends on the operating system of the installation host. See Microsoft Help and Support.

For more information about PowerShell Execution Policy, run help about_signing or help Set-ExecutionPolicy at the PowerShell command prompt.

.NOTES

1. Select Start > All Programs > Windows PowerShell > Windows PowerShell.

2. Script must be run as Windows Administrator

3. Run Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force. 
Note: If script does not run, try Set-ExecutionPolicy Unrestricted -Scope CurrentUser -Force.
                         Execution policies options:

                         Restricted - Scripts won’t run.
                         RemoteSigned - Scripts created locally will run, but those downloaded from the Internet will not (unless they are digitally signed by a trusted publisher).
                         AllSigned - Scripts will run only if they have been signed by a trusted publisher.
                         Unrestricted - Scripts will run regardless of where they have come from and whether they are signed.

4. Run the script

5. Verify that the command did not produce any errors.


.OUTPUTS
Files should be exported to "C:\ADA\<hostname>"

.EXAMPLE 
This example shows how to set the execution policy for the local computer.

 Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
 
This example shows how to run BSW script from local directory. 
 PS C:\"local directory"> .\BSW_System_Query_Script.ps1
#>

#Begin Transcript
# Determine script location for PowerShell
$ScriptDir = "C:\Windows"
 
$ErrorActionPreference="SilentlyContinue"
Stop-Transcript | out-null #Stop Transcript
$ErrorActionPreference="Continue"
Start-Transcript -path $ScriptDir'\Logs.txt' -append  #Begin Transcript 

# Detect if PowerShell is running as administrator - Start 
If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`

    [Security.Principal.WindowsBuiltInRole] “Administrator”))

{

    Write-Warning “You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!”

    Break

}

# Detect if PowerShell is running as administrator - End



write-host "ADA Windows Platform System Query Script Version 1.1
 ------------------------------------------------------------------------
Notice:
This script will now collect information from this system to be used for analysis, ADA.
No changes will be made to your system configuration. 
------------------------------------------------------------------------
Now gathering data, please wait...."
$confirmation = Read-Host "Is this a Domain Controller? [y/n]"

# Determining the environment
$systemname = $env:computername


 #ProductType
 #Data type: uint32
 #Access type: Read-only
 #Additional system information.
 #Workstation (1)
 #Domain Controller (2)
 #Server (3)
$osInfo = Get-WmiObject -Class Win32_OperatingSystem
$OSArchitecture = $osInfo.OSArchitecture # 64bit vs 32bit OS
$ProductType=$osInfo.ProductType # Server vs Domain Controller vs Workstation 
$Psversion=$psversiontable.psversion.major # Powershell version 
$OSName = $osInfo.caption # OS name and version 

#Creating ADA directory if it does not exist 
$path = "C:\ADA\"

If(!(test-path $path))

{New-Item -ItemType Directory -Path $path}

$fullpath = "C:\ADA\"+$systemname+"\"

If(!(test-path $fullpath))

{New-Item -ItemType Directory -Path $fullpath}

if ($ProductType -eq '1') {

write-host "This is a Workstation, running version" $psversiontable.psversion.major "of PowerShell on a" $OSArchitecture $OSName "OS" 
write-host "You will find the output in:" $fullpath
}




# Export All GPOs
write-host "Step 01/20 Querying GP Security Configuration"
#test if this is DC
 if ($ProductType -eq '2') { 
Get-GPOReport -All -ReportType HTML -Path $fullpath"8.5.9.gpresult.html"  
}

 if ($ProductType -ne '2') { 
GPRESULT /f /v  > $fullpath"8.5.9.gpresult.txt" # Applied and Not Applied Group Policy Objects
GPRESULT /f /H  $fullpath"8.5.9.gpresult.html"  # Full Html GPO Report 
}

# Windows System Information
write-host "Step 03/20 Getting System Information" 
Systeminfo > $fullpath"6.1.a.systeminfo.txt"

# Getting Domain User List
if ($confirmation -eq 'n') {
write-host "Skipping Step 04/20, Getting Domain User List" 
}
if ($confirmation -eq 'y') {
write-host "Step 04/20 Getting Domain User List" 

 <#  # proceed to Export All AD Objects Powershell 

Lastlogon is only updated on the domain controller that performs the authentication and is not replicated.

LastLogontimestamp is replicated, but by default only if it is 14 days or more older than the previous value.

#>


# AD computers
write-host "Processing AD computers ..." #added by Gene
Get-ADComputer -Filter * -Properties ipv4Address, OperatingSystem,LastLogonDate,LastLogonTimeStamp,description,whenCreated  | 
Select-Object Name, ipv4*, 
OperatingSystem,LastLogonDate,Description,@{Name="LastLogonStamp"; Expression={[DateTime]::FromFileTime($_.lastLogonTimestamp)}},WhenCreated |
 Sort LastLogondate -Descending  | 
Export-csv $fullpath"ADcomputers.csv" -NoTypeInformation


# Export AD users

                  Import-module activedirectory
                  $DaTA=@(
Get-ADUser  -filter * -Properties * |  
                  Select-Object @{Label = "FirstName";Expression = {$_.GivenName}},  
                  @{Name = "LastName";Expression = {$_.Surname}},
                  @{Name = "Full address";Expression = {$_.StreetAddress}},
                  @{Name = "Fullname";Expression = {$_.Name}},
                  @{Name = "LogonName";Expression = {$_.Samaccountname}},
                  @{Name = "City";Expression = {$_.City}}, 
                  @{Name = "State";Expression = {$_.st}}, 
                  @{Name = "Post Code";Expression = {$_.PostalCode}}, 
                  @{Name = "Country/Region";Expression ={$_.Country}},
                  @{Name = "MobileNumber";Expression = {$_.mobile}},
                  @{Name = "Phone";Expression = {$_.telephoneNumber}}, 
                  @{Name = "Description";Expression = {$_.Description}},
                  @{name =  "OU";expression={$_.DistinguishedName.split(',')[1].split('=')[1]}},
                  @{Name = "Email";Expression = {$_.Mail}},
                  @{Name = "MemberGroups"; Expression ={(($_.MemberOf).split(",") | where-object {$_.contains("CN=")}).replace("CN=","")-join ','}},
                  @{Name = "Primary Group";Expression= {$_.primarygroup  -replace '^CN=|,.*$'}},
                  @{Name = "UserPrincipalName";Expression = {$_.UserPrincipalName}},
                  @{Name = "LastLogonTimeSTamp";Expression = {if(($_.lastLogonTimestamp -like '*1/1/1601*' -or $_.lastLogonTimestamp -eq $null)){'NeverLoggedIn'} Else{[DateTime]::FromFileTime($_.lastLogonTimestamp)}}},
                  @{Name = "Account Status";Expression = {if (($_.Enabled -eq 'TRUE')  ) {'Enabled'} Else {'Disabled'}}},
                  @{Name = "LastLogonDate";Expression = {if(($_.lastlogondate -like '*1/1/1601*' -or $_.lastlogondate -eq $null)){'NeverLoggedIn'} Else{$_.lastlogondate}}},
                  @{Name = "WhenUserWasCreated";Expression = {$_.whenCreated}},
                  @{Name = "accountexpiratondate";Expression = {$_.accountexpiratondate}},
                  @{Name = "PasswordLastSet";Expression = {([DateTime]::FromFileTime($_.pwdLastSet))}},
                  @{Name = "PasswordExpiryDate";Expression={([datetime]::fromfiletime($_."msDS-UserPasswordExpiryTimeComputed")).DateTime}},
                  @{Name = "Password Never";Expression = {$_.passwordneverexpires}},
                  @{Name = "HomeDriveLetter";Expression = {$_.HomeDrive}},
                  @{Name = "HomeFolder";Expression = {$_.HomeDirectory}},
                  @{Name = "scriptpath";Expression = {$_.scriptpath}},
                  @{Name = "HomePage";Expression = {$_.HomePage}},
                  @{Name = "Department";Expression = {$_.Department}},
                  @{Name = "EmployeeID";Expression = {$_.EmployeeID}},
                  @{Name = "Job Title";Expression = {$_.Title}},
                  @{Name = "EmployeeNumber";Expression = {$_.EmployeeNumber}},
                  @{Name = "Manager";Expression={($_.manager -replace 'CN=(.+?),(OU|DC)=.+','$1')}}, 
                  @{Name = "Company";Expression = {$_.Company}},
                  @{Name = "Office";Expression = {$_.OfficeName}}
                  )
                  $DAta | Sort LastLogondate -Descending | 
                  Export-Csv -Path $fullpath"ADUsers.csv" -NoTypeInformation       
        
        
        # AD OrganizationalUnits
        write-host "Processing AD OrganizationalUnits ..." 
        Get-ADOrganizationalUnit -filter * | select Name,DistinguishedName,Description | 
        Export-csv -path $fullpath"ADOrganizationalUnits.csv" -NoTypeInformation
        
        # AD Contacts
		write-host "Processing AD Contacts ..." 
        Get-ADobject  -LDAPfilter "objectClass=contact" -Properties mail,Description,Mobile,ipPhone,homePhone,whenCreated | 
        Select-Object name,mail,Description,mobile,ipPhone,homePhone,whenCreated   | 
        Export-csv -path $fullpath"ADcontacts.csv" -NoTypeInformation
        
        # AD Groups
		write-host "Processing AD Groups ..."
        Get-ADgroup -Filter * -Properties members,whencreated,description,groupscope | 
        select name,samaccountname,groupscope,@{Name="Members"; Expression ={(($_.Members).split(",") | 
        where-object {$_.contains("CN=")}).replace("CN=","")-join ','}},whencreated,description | Sort-Object -Property Name|
         Export-csv -path $fullpath"ADGroups.csv" -NoTypeInformation

## Get AD users Group membership another way

Get-ADUser -filter * -Properties DisplayName,memberof | % {
  New-Object PSObject -Property @{
	UserName = $_.DisplayName
	Groups = ($_.memberof | Get-ADGroup | Select -ExpandProperty Name) -join ","
	}
} | Select UserName,Groups |Sort-Object -Property Name| Export-Csv $fullpath"Groupreport.csv" -NTI

## Gets the default password policy for an Active Directory domain
write-host "Processing default password policy for an Active Directory domain ..." 
(Get-ADForest -Current LoggedOnUser).Domains | %{ Get-ADDefaultDomainPasswordPolicy -Identity $_ } | Export-Csv $fullpath"DefaultDomainPasswordPolicy.csv" -NTI
} # End of Export All AD Objects Powershell 


# Local User Accounts
write-host "Step 05/20 Getting Local User Accounts" # Does not work on Server 2012 R2, add a different query and IF statement
# If Windows 10 or Server 2016   
if ($psversiontable.psversion.major -eq '5') {

Get-LocalUser  | Out-File $fullpath"7.1.local_user_accounts.txt"
}
else {
Get-WmiObject -Class win32_useraccount -filter "localaccount=true" | where {$_.disabled -eq $False} | Out-File $fullpath"7.1.local_user_accounts.txt"
}


# Getting Installed Products
write-host "Step 07/20 Getting Installed Products" 
Get-WmiObject -Class Win32_Product | Select-Object Name, Version | Sort-Object Name | out-file $fullpath"6.1.a.installed_products32.txt"
Get-ItemProperty HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*  | Select-Object DisplayName, Publisher, DisplayVersion, Brand | Sort-Object DisplayName | out-file $fullpath"6.1.a.installed_products64.txt"

# Getting Running Processes
write-host "Step 08/20 Getting Running Processes" 
Get-Process | Out-File $fullpath"2.2.1.Running_processes.txt"
# Need to add  starting Processes

# Getting Antivirus and Firewall Information
#productState=266240: This means AV has up to Date Definitions with ON Access Scanning turned ON
write-host "Step 10/20 Querying Antivirus and Firewall Information" 
# Workstation only 
if ($ProductType -eq '1') {

Get-WmiObject -Query "SELECT * FROM AntiVirusProduct" -NameSpace ROOT/SecurityCenter2  | Out-File $fullpath"5.1.av.txt" # Does not work on Windows Server 2012 R2
Get-NetFirewallProfile  | Out-File $fullpath"5.1.fw.txt"
}


# Getting Patch Information
write-host "Step 11/20 Qerying Patch Information" 
gwmi Win32_QuickFixEngineering | Out-File $fullpath"6.1.a.qfe.txt"
get-hotfix | Out-File $fullpath"6.1.a.all_hotfix.txt"
# Need to add query for missing or pending patches

# Getting Services
write-host "Step 13/20 Querying Services" 
get-service | Out-File $fullpath"2.2.2.Service.txt "

# Getting Filesystem Privileges
write-host "Step 14/20 Getting Filesystem Privileges" 
  function Get-Permissions ($folder) {
  (get-acl $folder).access | select `
		@{Label="Identity";Expression={$_.IdentityReference}}, `
		@{Label="Right";Expression={$_.FileSystemRights}}, `
		@{Label="Access";Expression={$_.AccessControlType}}, `
		@{Label="Inherited";Expression={$_.IsInherited}}, `
		@{Label="Inheritance Flags";Expression={$_.InheritanceFlags}}, `
		@{Label="Propagation Flags";Expression={$_.PropagationFlags}} | ft -auto
		}
Get-Permissions $env:SystemRoot\system32 | Out-File $fullpath"6.2.caclssystem32.txt"
Get-Permissions $env:SystemRoot\system32\config | Out-File $fullpath"6.2.caclssystem32config.txt"
Get-Permissions $env:SystemDrive | Out-File $fullpath"6.2.caclssystemdrive.txt"

# Getting Local Security Configuration
write-host "Step 15/20 Querying Local Security Configuration" 
secedit /export /cfg $fullpath"8.5.16.secedit.txt"

# Getting Installed Features
write-host "Step 16/20 Getting Installed Features" 

# for servers only # Get-WindowsFeature | Where-Object {$_. installstate -eq "installed"} | Format-List Name,Installstate | Out-File  $fullpath"6.1.a.Installed_Featurest.txt"

dism /online /get-features /format:list > $fullpath"6.1.a.dism_out.txt"

# Getting Registry Settings
write-host "Step 17/20 Querying Registry Settings" 

reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Terminal Server\WinStations\rdp-tcp" > $fullpath"2.3.1.reg.txt"
# reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0" > $fullpath"2.3.1.reg.txt"
# reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"  > $fullpath"2.3.1.reg.txt"
# reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities" > $fullpath"2.3.1.reg.txt"
# reg query "HKLM\SOFTWARE\InterSect Alliance\AuditService\Network" > $fullpath"2.3.1.reg.txt"
# reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\Oc Manager\Subcomponents" > $fullpath"2.3.1.reg.txt"
# reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Setup\Oc Manager\Subcomponents" > $fullpath"2.3.1.reg.txt"
# reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" > $fullpath"2.3.1.reg.txt"
# reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\eventlog\Application" > $fullpath"2.3.1.reg.txt"

# Getting Local Groups
write-host "Step 18/20 Querying Local Groups" 
# If Windows 10 or Server 2016   
if ($psversiontable.psversion.major -eq '5') {

Get-LocalGroup | Out-File $fullpath"7.2.2.localgroups.txt"
}
else {
Get-WmiObject -Class Win32_Group -filter "localaccount=true" | Out-File $fullpath"7.2.2.localgroups.txt"
}

Copy-Item "$ScriptDir\Logs.txt" -Destination $fullpath # Copy log file 

$source = $fullpath

$destination = $path+$systemname+".zip"
# Exporting Info
write-host "Step 20/20 Exporting to"$fullpath" and creating" $destination

 If(Test-path $destination) {Remove-item $destination}

Add-Type -assembly "system.io.compression.filesystem"

[io.compression.zipfile]::CreateFromDirectory($Source, $destination)  # zip all files

# Hashing a zip file under PS 5   
if ($psversiontable.psversion.major -eq '5') {

$hash = Get-FileHash $destination -Algorithm MD5
write   $hash | Add-Content -Path  $path$systemname".md5" 
}
else {
$hash = CertUtil -hashfile $destination MD5 # hashing a zip file under  other PS versions   
write   $hash | Add-Content -Path  $path$systemname".md5" 
}

write-host "Done!" 

Stop-Transcript | out-null #Stop Transcript



# SIG # Begin signature block
# MIIONQYJKoZIhvcNAQcCoIIOJjCCDiICAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUisnL+/E1NJ16i7KKWVX/1br4
# pPOgggtsMIIFbzCCBFegAwIBAgIRAPhZF5jN9xy4U15ARnOBnj0wDQYJKoZIhvcN
# AQELBQAwfDELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3Rl
# cjEQMA4GA1UEBxMHU2FsZm9yZDEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMSQw
# IgYDVQQDExtTZWN0aWdvIFJTQSBDb2RlIFNpZ25pbmcgQ0EwHhcNMTkwNDAyMDAw
# MDAwWhcNMjAwNDAxMjM1OTU5WjCBwDELMAkGA1UEBhMCVVMxDjAMBgNVBBEMBTYz
# MTQxMREwDwYDVQQIDAhNaXNzb3VyaTEUMBIGA1UEBwwLU2FpbnQgTG91aXMxEDAO
# BgNVBAkMB1NURSA5MDAxFzAVBgNVBAkMDjYgQ2l0eXBsYWNlIERyMRwwGgYDVQQK
# DBNCcm93biBTbWl0aCBXYWxsYWNlMREwDwYDVQQLDAhTZWN1cml0eTEcMBoGA1UE
# AwwTQnJvd24gU21pdGggV2FsbGFjZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
# AQoCggEBAMv364A1880KT7JLYmyT/DIJjYXQ5OSJxftGyBO/itdmlBJaH4ngoMCQ
# 0Kx++MsZquDBtsuvP2buUhA1kDpHWNvymwHuCKJG+FoYgTlAeBZ4fsqh3Z8T31Jz
# WKWzmyIJszqdd4iQSS1KfQ4LZisas8FLLCrLgPWtu4aJEKmvF5QSHJsWohGpzlUQ
# ZGp56E9Rf3yVmhx4jFjphTL1sKYWkYC3WMPTmfj99vx1KbAs4k2q/hOm+B9Vb2Vg
# lP7KaPvT/FhopoFaerL3G69SOiSwDtf2Piz61zjnCe5GzWQE1qychhH0Q3tHCoDu
# wiDKGOAEJ+Xz3DKOXWtawBLtNMMGXccCAwEAAaOCAaUwggGhMB8GA1UdIwQYMBaA
# FA7hOqhTOjHVir7Bu61nGgOFrTQOMB0GA1UdDgQWBBTXABI1D13+aEnhNPaV8OtM
# uUnopzAOBgNVHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggr
# BgEFBQcDAzARBglghkgBhvhCAQEEBAMCBBAwQAYDVR0gBDkwNzA1BgwrBgEEAbIx
# AQIBAwIwJTAjBggrBgEFBQcCARYXaHR0cHM6Ly9zZWN0aWdvLmNvbS9DUFMwQwYD
# VR0fBDwwOjA4oDagNIYyaHR0cDovL2NybC5zZWN0aWdvLmNvbS9TZWN0aWdvUlNB
# Q29kZVNpZ25pbmdDQS5jcmwwcwYIKwYBBQUHAQEEZzBlMD4GCCsGAQUFBzAChjJo
# dHRwOi8vY3J0LnNlY3RpZ28uY29tL1NlY3RpZ29SU0FDb2RlU2lnbmluZ0NBLmNy
# dDAjBggrBgEFBQcwAYYXaHR0cDovL29jc3Auc2VjdGlnby5jb20wHQYDVR0RBBYw
# FIESc3NsQHNlY3VyaXR5bGFiLmlvMA0GCSqGSIb3DQEBCwUAA4IBAQBY+fnjSTDC
# wXTqr2eziCit2BFUqLiZrWdqHh5jIGS1YCDBrvkv+QgT7jJzJrdlQGngBOb0QNov
# F6g+LzwBQXlxvArYzYlwzKlWG0u9+jUOmjDlIsRcJp7D1Hon0Rmm77QCg5tsyyq9
# eKMSQ5+urH5+UXLhaNEv8Qeef39qHomu4a0K2Ido6k8DcHa/MQBioji8SR0cPWn6
# TvhUFfuxY5wy/AeZRWUpJxXZKoPJ1aBydPjw0ExIIFxwq7471YdMxJGqQ4rStSDM
# StbLlQPYKQylzHzo60qUERoW2aef8Wd+dBQjuM4VJs0zT43bD32giu8qUGzx3d0U
# +DU+PpGBnZyJMIIF9TCCA92gAwIBAgIQHaJIMG+bJhjQguCWfTPTajANBgkqhkiG
# 9w0BAQwFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCk5ldyBKZXJzZXkxFDAS
# BgNVBAcTC0plcnNleSBDaXR5MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNUIE5ldHdv
# cmsxLjAsBgNVBAMTJVVTRVJUcnVzdCBSU0EgQ2VydGlmaWNhdGlvbiBBdXRob3Jp
# dHkwHhcNMTgxMTAyMDAwMDAwWhcNMzAxMjMxMjM1OTU5WjB8MQswCQYDVQQGEwJH
# QjEbMBkGA1UECBMSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHEwdTYWxmb3Jk
# MRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxJDAiBgNVBAMTG1NlY3RpZ28gUlNB
# IENvZGUgU2lnbmluZyBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
# AIYijTKFehifSfCWL2MIHi3cfJ8Uz+MmtiVmKUCGVEZ0MWLFEO2yhyemmcuVMMBW
# 9aR1xqkOUGKlUZEQauBLYq798PgYrKf/7i4zIPoMGYmobHutAMNhodxpZW0fbieW
# 15dRhqb0J+V8aouVHltg1X7XFpKcAC9o95ftanK+ODtj3o+/bkxBXRIgCFnoOc2P
# 0tbPBrRXBbZOoT5Xax+YvMRi1hsLjcdmG0qfnYHEckC14l/vC0X/o84Xpi1VsLew
# vFRqnbyNVlPG8Lp5UEks9wO5/i9lNfIi6iwHr0bZ+UYc3Ix8cSjz/qfGFN1VkW6K
# EQ3fBiSVfQ+noXw62oY1YdMCAwEAAaOCAWQwggFgMB8GA1UdIwQYMBaAFFN5v1qq
# K0rPVIDh2JvAnfKyA2bLMB0GA1UdDgQWBBQO4TqoUzox1Yq+wbutZxoDha00DjAO
# BgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHSUEFjAUBggr
# BgEFBQcDAwYIKwYBBQUHAwgwEQYDVR0gBAowCDAGBgRVHSAAMFAGA1UdHwRJMEcw
# RaBDoEGGP2h0dHA6Ly9jcmwudXNlcnRydXN0LmNvbS9VU0VSVHJ1c3RSU0FDZXJ0
# aWZpY2F0aW9uQXV0aG9yaXR5LmNybDB2BggrBgEFBQcBAQRqMGgwPwYIKwYBBQUH
# MAKGM2h0dHA6Ly9jcnQudXNlcnRydXN0LmNvbS9VU0VSVHJ1c3RSU0FBZGRUcnVz
# dENBLmNydDAlBggrBgEFBQcwAYYZaHR0cDovL29jc3AudXNlcnRydXN0LmNvbTAN
# BgkqhkiG9w0BAQwFAAOCAgEATWNQ7Uc0SmGk295qKoyb8QAAHh1iezrXMsL2s+Bj
# s/thAIiaG20QBwRPvrjqiXgi6w9G7PNGXkBGiRL0C3danCpBOvzW9Ovn9xWVM8Oh
# gyi33i/klPeFM4MtSkBIv5rCT0qxjyT0s4E307dksKYjalloUkJf/wTr4XRleQj1
# qZPea3FAmZa6ePG5yOLDCBaxq2NayBWAbXReSnV+pbjDbLXP30p5h1zHQE1jNfYw
# 08+1Cg4LBH+gS667o6XQhACTPlNdNKUANWlsvp8gJRANGftQkGG+OY96jk32nw4e
# /gdREmaDJhlIlc5KycF/8zoFm/lv34h/wCOe0h5DekUxwZxNqfBZslkZ6GqNKQQC
# d3xLS81wvjqyVVp4Pry7bwMQJXcVNIr5NsxDkuS6T/FikyglVyn7URnHoSVAaoRX
# xrKdsbwcCtp8Z359LukoTBh+xHsxQXGaSynsCz1XUNLK3f2eBVHlRHjdAd6xdZgN
# VCT98E7j4viDvXK6yz067vBeF5Jobchh+abxKgoLpbn0nu6YMgWFnuv5gynTxix9
# vTp3Los3QqBqgu07SqqUEKThDfgXxbZaeTMYkuO1dfih6Y4KJR7kHvGfWocj/5+k
# UZ77OYARzdu1xKeogG/lU9Tg46LC0lsa+jImLWpXcBw8pFguo/NbSwfcMlnzh6ca
# bVgxggIzMIICLwIBATCBkTB8MQswCQYDVQQGEwJHQjEbMBkGA1UECBMSR3JlYXRl
# ciBNYW5jaGVzdGVyMRAwDgYDVQQHEwdTYWxmb3JkMRgwFgYDVQQKEw9TZWN0aWdv
# IExpbWl0ZWQxJDAiBgNVBAMTG1NlY3RpZ28gUlNBIENvZGUgU2lnbmluZyBDQQIR
# APhZF5jN9xy4U15ARnOBnj0wCQYFKw4DAhoFAKB4MBgGCisGAQQBgjcCAQwxCjAI
# oAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIB
# CzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFBiGuptaiIcP32SFeEiE
# cQNay2mfMA0GCSqGSIb3DQEBAQUABIIBABWzbg+a80LtUy2rNvIVY0j8QHU8YRqW
# cBn4pBI/JTY6qXmLdFSR1IFy5oEmrN9YeyuCrcDC/0XternR5Tu7BVPN2bD43Wbd
# 0MnJlfwaPpqXIrqpozcW2aNoBuRJP8ccfHLOvpB+MWYrwhF0BLpz0y4rpr9zNZz4
# zVAuIP0AMfhn+VgKE/skpKyfVdQT4Y6HLIp8UiNtFCdLVsrE+KwWWNTSlQaQ4Wnk
# wHMtn3X8Xre8rktY5TnS9SQoQlTlWm83LKM6Li1uJWNUhKpm4UtCE8MfJ7m+Ai1G
# Cwp9rnBCgB87whIqh0Mc8hFHKz4sNi+q6Ln3RZNnBfwXS8kWCb2qNzE=
# SIG # End signature block
