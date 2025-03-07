##*=============================================
##* ABOUT  
##*============================================= 

## PowerShell script to determine if an upgrade is required for Sysmon. 
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

$FolderCheckLeaf = Test-Path -Path C:\Temp -PathType Leaf
$FolderCheckContainer = Test-Path -Path C:\Temp -PathType Container

##*=============================================  
##* END VARIABLE LISTINGS
##*=============================================  

##*=============================================  
##* SCRIPT BODY  
##*=============================================  

###############################################################  
##### Validate Required Folder Structure for File Storage #####  
###############################################################  

If (($FolderCheckLeaf -eq $true) -or ($FolderCheckContainer -eq $false))
{
    Remove-Item -Path C:\Temp -Force -ErrorAction SilentlyContinue | Out-Null
    New-Item -ItemType Directory -Path C:\Temp -Force | Out-Null;
    
    $FolderCheckLeaf = Test-Path -Path C:\Temp -PathType Leaf
    $FolderCheckContainer = Test-Path -Path C:\Temp -PathType Container
}

If ($FolderCheckContainer -eq $true)
{
    Set-Location C:\Temp
    
    #############################################  
    ##### Download Latest Version of Sysmon #####  
    #############################################  
    
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri https://download.sysinternals.com/files/Sysmon.zip -Outfile SysMon.zip
    
    If (Test-Path -Path C:\Temp\SysMon.zip)
    {
        ###############################  
        ##### Expand Zip Archieve #####  
        ###############################  
        
        Expand-Archive SysMon.zip -Force
        
        Set-Location C:\Temp\SysMon
        
        ######################################  
        ##### Uninstall Previous Version #####  
        ######################################  
        
        Set-Location C:\Windows
        
        $TimeStart = Get-Date
        $TimeEnd = $TimeStart.AddSeconds(30)
        
        Start-Process -FilePath C:\Windows\Sysmon.exe -ArgumentList "-u"
        
        Do
        {
            $Uninstall_InProgress = Get-Process -Name Sysmon -ErrorAction SilentlyContinue
            $TimeNow = Get-Date
        }
        Until (!($Uninstall_InProgress) -or ($TimeNow -ge $TimeEnd))
        
        ###############################  
        ##### Install New Version #####  
        ###############################  
        
        Set-Location C:\Temp\SysMon
        
        $TimeStart = Get-Date
        $TimeEnd = $TimeStart.AddSeconds(30)
        
        Start-Process -FilePath .\Sysmon.exe -ArgumentList '-i -accepteula'
        
        Do
        {
            $Uninstall_InProgress = Get-Process -Name Sysmon -ErrorAction SilentlyContinue
            $TimeNow = Get-Date
        }
        Until (!($Uninstall_InProgress) -or ($TimeNow -ge $TimeEnd))
        
        #################################  
        ##### Cleanup Install Files #####  
        #################################  
        
        Set-Location C:\WINDOWS\system32
        
        Remove-Item -Path C:\Temp\SysMon.zip -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
        Remove-Item -path C:\Temp\SysMon -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
    }
}

##*=============================================  
##* END SCRIPT BODY  
##*=============================================  