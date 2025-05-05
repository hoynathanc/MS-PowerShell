##*=============================================
##* ABOUT
##*=============================================

<#
.SYNOPSIS
	Discovery of User Sessions on Servers
.AUTHOR
    Nathan C. Hoy (nchoy) | Endpoint Engineer
#>

##*=============================================
##* END ABOUT
##*=============================================

##*=============================================
##* FUNCTION LISTINGS
##*=============================================

##*=============================================
##* END FUNCTION LISTINGS
##*=============================================

##*=============================================
##* VARIABLE LISTINGS
##*=============================================

$Domain = "DOMAIN" ##Modify for Your Domain
$Servers = Get-ADComputer -Server $Domain -Filter {(Enabled -eq $true) -and (OperatingSystem -like "*server*")} | Sort-Object -Property $_.Name
$URI = "URL"

$Results = @()

$HelpdeskTeam_Users = @(
	##Include Your Members Here
)

$ServerTeam_Users = @(
	##Include Your Members Here
)

$SecurityTeam_Users = @(
	## Include Your Members Here
)

##*=============================================
##* END VARIABLE LISTINGS
##*=============================================

##*=============================================
##* SCRIPT BODY
##*=============================================

$FullScriptStartTime = [System.DateTime]::Now

ForEach ($Server in $Servers)
{
	$Online_Status = Test-Connection -ComputerName $Server.Name -Count 1
	$IP = $Online_Status.IPV4Address.IPAddressToString
	
	If (($IP -ne $null) -and ($IP -notlike "172*")) ## Exclude DMZ Servers
	{
		$Session = (qwinsta /server $($Server).Name | foreach { (($_.trim() -replace "\s+", ",")) } | ConvertFrom-Csv)
		$QueryDisconnect = $Session.SessionName
		$QueryActive = $Session.Username
		
		###################
		## Helpdesk Team ##
		###################
		
		$Server.Name
		
		$QueryDisconnect | ForEach-Object {
			If ($_ -in $HelpdeskTeam_Users)
			{
				$Object = New-Object -TypeName PSObject
				$Object | Add-Member -type NoteProperty -Name "Server" $Server.Name
				$Object | Add-Member -type NoteProperty -Name "User" $_
				$Object | Add-Member -type NoteProperty -Name "Session" "Disconnect"
				
				$TimeStamp = [System.DateTime]::Now.ToString()
				
				$Object | Add-Member -type NoteProperty -Name "TimeStamp" "$TimeStamp"
				$Object | Add-Member -type NoteProperty -Name "Team" "Helpdesk"
				
				$Results += $Object				
			}
		}
		
		$QueryActive | ForEach-Object {
			If ($_ -in $HelpdeskTeam_Users)
			{
				$Object = New-Object -TypeName PSObject
				$Object | Add-Member -type NoteProperty -Name "Server" $Server.Name
				$Object | Add-Member -type NoteProperty -Name "User" $_
				$Object | Add-Member -type NoteProperty -Name "Session" "Active"
				
				$TimeStamp = [System.DateTime]::Now.ToString()
				
				$Object | Add-Member -type NoteProperty -Name "TimeStamp" "$TimeStamp"
				$Object | Add-Member -type NoteProperty -Name "Team" "Helpdesk"
				
				$Results += $Object				
			}
		}
		
		#################
		## Server Team ##
		#################
		
		$QueryDisconnect | ForEach-Object {
			If ($_ -in $ServerTeam_Users)
			{
				$Object = New-Object -TypeName PSObject
				$Object | Add-Member -type NoteProperty -Name "Server" $Server.Name
				$Object | Add-Member -type NoteProperty -Name "User" $_
				$Object | Add-Member -type NoteProperty -Name "Session" "Disconnect"
				
				$TimeStamp = [System.DateTime]::Now.ToString()
				
				$Object | Add-Member -type NoteProperty -Name "TimeStamp" "$TimeStamp"
				$Object | Add-Member -type NoteProperty -Name "Team" "Server"
				
				$Results += $Object		
			}
		}
		
		$QueryActive | ForEach-Object {
			If ($_ -in $ServerTeam_Users)
			{
				$Object = New-Object -TypeName PSObject
				$Object | Add-Member -type NoteProperty -Name "Server" $Server.Name
				$Object | Add-Member -type NoteProperty -Name "User" $_
				$Object | Add-Member -type NoteProperty -Name "Session" "Active"
				
				$TimeStamp = [System.DateTime]::Now.ToString()
				
				$Object | Add-Member -type NoteProperty -Name "TimeStamp" "$TimeStamp"
				$Object | Add-Member -type NoteProperty -Name "Team" "Server"
				
				$Results += $Object	
			}
		}
		
		###################
		## Security Team ##
		###################
		
		$QueryDisconnect | ForEach-Object {
			If ($_ -in $SecurityTeam_Users)
			{
				$Object = New-Object -TypeName PSObject
				$Object | Add-Member -type NoteProperty -Name "Server" $Server.Name
				$Object | Add-Member -type NoteProperty -Name "User" $_
				$Object | Add-Member -type NoteProperty -Name "Session" "Disconnect"
				
				$TimeStamp = [System.DateTime]::Now.ToString()
				
				$Object | Add-Member -type NoteProperty -Name "TimeStamp" "$TimeStamp"
				$Object | Add-Member -type NoteProperty -Name "Team" "Security"
				
				$Results += $Object			
			}
		}
		
		$QueryActive | ForEach-Object {
			If ($_ -in $SecurityTeam_Users)
			{
				$Object = New-Object -TypeName PSObject
				$Object | Add-Member -type NoteProperty -Name "Server" $Server.Name
				$Object | Add-Member -type NoteProperty -Name "User" $_
				$Object | Add-Member -type NoteProperty -Name "Session" "Active"
				
				$TimeStamp = [System.DateTime]::Now.ToString()
				
				$Object | Add-Member -type NoteProperty -Name "TimeStamp" "$TimeStamp"
				$Object | Add-Member -type NoteProperty -Name "Team" "Security"
				
				$Results += $Object				
			}
		}
	}
	Else
	{
		$Offline_Servers += $Server.Name
	}
}

############################
##### Publish to Teams #####
############################

$Header = @"
        <style>
        TABLE {border-width: 1px; border-style: solid; border-color: black; border-collapse: collapse;}
        TH {border-width: 1px; padding: 3px; border-style: solid; border-color: black; background-color: #6495ED;}
        TD {border-width: 1px; padding: 3px; border-style: solid; border-color: black;}
        </style>
"@

$Body = $Results | Sort-Object -Property Team | ConvertTo-Html

If ($Results.Count -gt 0)
{
    Invoke-RestMethod -uri $URI -Method Post -body "{'title': 'Active and Disconnected User Sessions', 'activityTitle': 'User Sessions', 'themeColor': 'ff1717',  'text': '$Body'}" -ContentType 'application/json' -ErrorAction SilentlyContinue
}
##*=============================================
##* END SCRIPT BODY
##*=============================================