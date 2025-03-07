##*=============================================
##* VARIABLE LISTINGS
##*=============================================
$Date = Get-Date -Format 'MMMdd_HHMMttss'
# Application Details - ModIfy Script Details
[string]$appVendor = 'In House'
[string]$appName = 'PhysicalDiskDiscovery' ## Update Me
[string]$appNameWithSpaces = "Physical Disk Discovery" ## Update Me
[string]$appVersion = '1.1.0.0' ## Update Me
[string]$appTitle = "$appVendor $appName $appVersion"
[string]$appArch = 'x64x86' ## Update Me (If Needed)
[string]$appLang = 'EN'
[string]$appRevision = '01'
[string]$appScriptVersion = '1.1.0.0' ## Update Me
[string]$appScriptDate = '04/11/2023' ## Update Me
[string]$appScriptAuthor = 'Nathan C. Hoy - nchoy' ## Update Me
[string]$LogRegKey = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\FCDC-HD"
[string]$runtime = '5'
#region DONOTMODIfY
# Log File Info 
$LogPath = 'C:\Windows\HD\Logs'
$LogName = "$appName" + "_" + "$appScriptVersion" + "_" + "PS.log"
$LogFile = Join-Path -Path $LogPath -ChildPath $LogName
$FolderCheckLeaf = Test-Path -Path $LogPath -PathType Leaf
$FolderCheckContainer = Test-Path -Path $LogPath -PathType Container
# Repo File Info
$RepoPath = 'C:\Windows\HD\Repo'
$RepoCheckLeaf = Test-Path -Path $RepoPath -PathType Leaf
$RepoCheckContainer = Test-Path -Path $RepoPath -PathType Container
# Specs and Details
$PackageName = (Get-Process -Id $PID).ProcessName
$SerialNumber = (Get-WmiObject win32_bios).serialnumber
$Manufacturer = (Get-WmiObject win32_bios).Manufacturer
$BIOsVerison = (Get-WmiObject win32_bios).SMBIOSBIOSVersion
$Model = (Get-WmiObject win32_computersystem).Model
$Name = (Get-WmiObject win32_computersystem).Name
$GB = Get-WmiObject win32_LogicalDisk | Measure-Object -Sum Size
$GB2 = Get-WmiObject win32_LogicalDisk | Measure-Object -Sum freespace
$Disk = "{0:N2}" -f ($GB.Sum / 1GB) + " GB"
$FreeSpace = "{0:N2}" -f ($gb2.sum / 1GB) + " GB"
[psobject]$envOS = Get-WmiObject -Class 'Win32_OperatingSystem' -ErrorAction 'SilentlyContinue'
[string]$envOSName = $envOS.Caption.Trim()
[string]$envOSServicePack = $envOS.CSDVersion
[version]$envOSVersion = $envOS.Version
[string]$envOSVersionMajor = $envOSVersion.Major
[string]$envOSVersionMinor = $envOSVersion.Minor
[string]$envOSVersionBuild = $envOSVersion.Build
[string]$envOSVersionRevision = ,((Get-ItemProperty -Path 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'BuildLabEx' -ErrorAction 'SilentlyContinue').BuildLabEx -split '\.') | ForEach-Object { $_[1] }
If ($envOSVersionRevision -notmatch '^[\d\.]+$') { $envOSVersionRevision = '' }
If ($envOSVersionRevision) { [string]$envOSVersion = "$($envOSVersion.ToString()).$envOSVersionRevision" }
Else { "$($envOSVersion.ToString())" }
#endregion
# Custom Items
$SubFolderExist = $false
$MediaTypes = ""
$FriendlyName = ""
##*=============================================
##* END VARIABLE LISTINGS
##*=============================================
##*=============================================
##* FUNCTION LISTINGS
##*=============================================
#region Log Functions
Function Start-Log
{
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$LogPath,
        [Parameter(Mandatory = $true, Position = 1)]
        [string]$LogName,
        [Parameter(Mandatory = $true, Position = 2)]
        [string]$ScriptVersion
    )
    
    Process
    {
        #Create file and start logging
        If (!(Test-Path -Path $LogFile))
        {
            New-Item -Path $LogFile -ItemType File
        }
        Add-Content -Path $LogFile -Value "***************************************************************************************************"
        Add-Content -Path $LogFile -Value "Started processing at [$([DateTime]::Now)]."
        Add-Content -Path $LogFile -Value "***************************************************************************************************"
        Add-Content -Path $LogFile -Value ""
        Add-Content -Path $LogFile -Value "Running script version [$ScriptVersion]."
        Add-Content -Path $LogFile -Value ""
        Add-Content -Path $LogFile -Value "***************************************************************************************************"
        Add-Content -Path $LogFile -Value "                                                               Package Information"
        Add-Content -Path $LogFile -Value "***************************************************************************************************"
        Add-Content -Path $LogFile -Value ""
        Add-Content -Path $LogFile -Value "Package Name = [$appNameWithSpaces]"
        Add-Content -Path $LogFile -Value "App Version = [$appVersion]"
        Add-Content -Path $LogFile -Value "Script Version = [$appScriptVersion]"
        Add-Content -Path $LogFile -Value ""
        Add-Content -Path $LogFile -Value "***************************************************************************************************"
        Add-Content -Path $LogFile -Value "                                                               System Information"
        Add-Content -Path $LogFile -Value "***************************************************************************************************"
        Add-Content -Path $LogFile -Value ""
        Add-Content -Path $LogFile -Value "Name = [$Name]"
        Add-Content -Path $LogFile -Value "OS Name= [$envOSName]"
        Add-Content -Path $LogFile -Value "OS Version= [$envOSVersion]"
        Add-Content -Path $LogFile -Value "Serial Number= [$SerialNumber]"
        Add-Content -Path $LogFile -Value "BIOS Version = [$BIOsVerison]"
        Add-Content -Path $LogFile -Value "Manufacturer = [$Manufacturer]"
        Add-Content -Path $LogFile -Value "Model = [$Model]"
        Add-Content -Path $LogFile -Value "Total Disk Size = [$Disk]"
        Add-Content -Path $LogFile -Value "Free Disk Space = [$FreeSpace]"
        Add-Content -Path $LogFile -Value ""
        Add-Content -Path $LogFile -Value "***************************************************************************************************"
    }
}
Function Write-PoShLog
{
    [CmdletBinding()]
    [OutputType([object[]])]
    Param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        $Message
    )
    
    Process
    {
        $Message = "$Message  [$([DateTime]::Now)]"
        $LogPath = $LogFile
        
        #Write Content to Log
        Add-Content  $LogPath -Value $Message
    }
}
Function Stop-Log
{
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$LogPath,
        [Parameter(Mandatory = $false, Position = 1)]
        [switch]$NoExit
        
    )
    
    Process
    {
        Add-Content -Path $LogPath -Value ""
        Add-Content -Path $LogPath -Value "***************************************************************************************************"
        Add-Content -Path $LogPath -Value "Finished processing at [$([DateTime]::Now)]."
        Add-Content -Path $LogPath -Value "***************************************************************************************************"
        
        #Exit calling script If NoExit has not been specIfied or is set to False
        If (!($NoExit) -or ($NoExit -eq $False))
        {
            Exit
        }
    }
}
#endregion
##*=============================================
##* END FUNCTION LISTINGS
##*=============================================
##*=============================================
##* SCRIPT BODY
##*=============================================
# Log Path
If (($FolderCheckLeaf -eq $true) -or ($FolderCheckContainer -eq $false))
{
    Remove-Item -Path $LogPath -Force -ErrorAction SilentlyContinue | Out-Null
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null;
    
    $FolderCheckLeaf = Test-Path -Path $LogPath -PathType Leaf
    $FolderCheckContainer = Test-Path -Path $LogPath -PathType Container
}
# Repo Path
If (($RepoCheckLeaf -eq $true) -or ($RepoCheckContainer -eq $false))
{
    Remove-Item -Path $RepoPath -Force -ErrorAction SilentlyContinue | Out-Null
    New-Item -ItemType Directory -Path $RepoPath -Force | Out-Null;
    
    $RepoCheckLeaf = Test-Path -Path $RepoPath -PathType Leaf
    $RepoCheckContainer = Test-Path -Path $RepoPath -PathType Container
}
## Validate Repo and Log Paths
If (($FolderCheckContainer -eq $true) -and ($RepoCheckContainer -eq $true))
{
    Start-Log -LogPath $LogPath -LogName $LogName -ScriptVersion $appScriptVersion | Out-Null
    
    #region : Initial Registry Key Entries - DO NOT MODIfY
    
    If (!(Test-Path "$LogRegKey\$appVendor\$appName\$appVersion"))
    {
        New-Item "$LogRegKey\$appVendor\$appName\$appVersion" -Force | Out-Null
    }
    
    Set-ItemProperty "$LogRegKey\$appVendor\$appName\$appVersion" -Name "AppTitle" -Value $appNameWithSpaces -Force
    Set-ItemProperty "$LogRegKey\$appVendor\$appName\$appVersion" -Name "ComputerName" -Value $env:COMPUTERNAME -Force
    Set-ItemProperty "$LogRegKey\$appVendor\$appName\$appVersion" -Name "StartTime" -Value "$(Get-Date)" -Force
    Set-ItemProperty "$LogRegKey\$appVendor\$appName\$appVersion" -Name "ScriptVersion" -Value $appScriptVersion -Force
    Set-ItemProperty "$LogRegKey\$appVendor\$appName\$appVersion" -Name "UserID" -Value ([Environment]::UserDomainName + "\" + [Environment]::UserName) -Force
    
    $appVer = $appVersion
    $appVendorfinal = $appvendor
    $appnamefinal = $appName
    
    #endregion
    
    
    ## Perform Discovery
    
    $DisksInfo = @(Get-PhysicalDisk | Where { $_.BusType -ne "USB" } | Select FriendlyName, MediaType)
    
    $DisksInfo | ForEach { $MediaTypes += $_.MediaType + "," }
    $DisksInfo | ForEach { $FriendlyName += $_.FriendlyName + "," }
    
    If (($MediaTypes -like "*SSD*") -and ($MediaTypes -notlike "*HDD*"))
    {
        $PrimaryDisk = "SSD"
    }
    ElseIf (($MediaTypes -notlike "*SSD*") -and ($MediaTypes -like "*HDD*"))
    {
        $PrimaryDisk = "HDD"
    }
    ElseIf (($MediaTypes -like "*SSD*") -and ($MediaTypes -like "*HDD*"))
    {
        $PrimaryDisk = "Unknown"
    }
    Else
    {
        $PrimaryDisk = "Other"
    }
    
    ## Tattoo results within the registry
    
    Set-ItemProperty "$LogRegKey\$appVendorfinal\$appnamefinal\$appVer" -Name "PrimaryDiskMediaType" -Value "$PrimaryDisk" -Force
    Set-ItemProperty "$LogRegKey\$appVendorfinal\$appnamefinal\$appVer" -Name "DisksMediaTypes" -Value "$($MediaTypes.TrimEnd(','))" -Force
    Set-ItemProperty "$LogRegKey\$appVendorfinal\$appnamefinal\$appVer" -Name "DisksFriendlyName" -Value "$($FriendlyName.TrimEnd(','))" -Force
    Set-ItemProperty "$LogRegKey\$appVendorfinal\$appnamefinal\$appVer" -Name "EndTime" -Value "$(Get-Date)" -Force
    Set-ItemProperty "$LogRegKey\$appVendorfinal\$appnamefinal\$appVer" -Name "Installed" -Value "0" -Force
    
    Stop-Log -LogPath $LogFile
    #[Environment]::Exit        
}
##*=============================================
##* END SCRIPT BODY
##*=============================================