##*=============================================
##* ABOUT
##*=============================================

# Discovery Script for Identify Mobile Phones Connected to Exchange
# Goals
# Identify Connected Mobile Devices
# Identify Connection Method
# Identify Agency for User

##*=============================================
##* END ABOUT
##*=============================================

##*=============================================
##* VARIABLE LISTINGS
##*=============================================

$FileDate = Get-Date -Format 'MMMdd_HHMMss'
$StartTime = Get-Date
$FileOutput = "$PSScriptRoot\DeviceInfo_$FileDate.csv"

$mobileDevice = @()
$Report = @()

$counter = 0

##*=============================================
##* END VARIABLE LISTINGS
##*=============================================

##*=============================================
##* FUNCTION LISTINGS
##*=============================================

##*=============================================
##* END FUNCTION LISTINGS
##*=============================================

##*=============================================
##* SCRIPT BODY
##*=============================================

############################
###### Connect to M365 #####
############################

If (Get-Module -ListAvailable -Name ExchangeOnlineManagement)
{
    Connect-ExchangeOnline
    
    Write-Host "Gathering Mailbox Data. Please Wait....."
    
    $mailboxUsers = Get-Mailbox -resultsize unlimited -RecipientTypeDetails UserMailbox -ErrorAction SilentlyContinue
    $total = $mailboxUsers.count
    
    ForEach ($user in $mailboxUsers)
    {
        $counter++
        
        $UPN = $user.UserPrincipalName
        $displayName = $user.DisplayName
        
        Write-Progress -Activity "Mailbox Statistics - $UPN " -Status "$counter of $total"
        
        Start-Sleep -m 1000 ## https://support.microsoft.com/en-us/topic/-micro-delay-applied-warning-or-delays-occur-in-exchange-online-86716b03-53ff-d07f-3b24-b638a9f6b733
        
        ###################################
        ##### Grab Mobile Device Info #####
        ###################################
        
        $MobileDeviceResults = Get-MobileDeviceStatistics -Mailbox $UPN -ErrorAction SilentlyContinue; Start-Sleep -Seconds 10
        
        ############################
        ##### Grab Agency Info #####
        ############################
        
        $LicenseGroup = Get-Aduser -filter { UserPrincipalName -eq $upn } -ErrorAction SilentlyContinue | Get-ADPrincipalGroupMembership -ErrorAction SilentlyContinue | Where { $_.SamAccountName -like "*-M365-Licensing" }
        
        If ($LicenseGroup)
        {
            $Agency = $LicenseGroup.SamAccountName
        }
        Else
        {
            $Agency = "NULL"
        }
        
        ForEach ($Result in $MobileDeviceResults)
        {
            $Object = New-Object PsObject
            
            ForEach ($key in $Result[0].psobject.properties.Name)
            {
                $Object | Add-Member NoteProperty $key $Result.$key
                
                ##################################
                ##### Check for Last 90 Days #####
                ##################################
                
                If ($key -eq "LastSuccessSync")
                {
                    $LastSuccessSyncDate = $Result.$key
                    $CurrentDate = Get-Date
                    
                    If ($LastSuccessSyncDate -lt (Get-Date).AddDays(-90))
                    {
                        $Object | Add-Member NoteProperty LastCommunication "Older Than 90"
                    }
                    Else
                    {
                        $Object | Add-Member NoteProperty LastCommunication "Less Than 90"
                    }
                }
            }
            
            $Object | Add-Member NoteProperty Agency $Agency
            $Report += $Object
        }
    }
}
Else
{
    Write-Host "ExchangeOnlineManagement Module Not Installed. Perform Install-Module ExchangeOnlineManagement prior to running scipt."
}

##########################
##### Export Results #####
##########################

$Report | Export-Csv -notypeinformation -Path $FileOutput
$EndTime = Get-Date

##*=============================================
##* END SCRIPT BODY
##*=============================================