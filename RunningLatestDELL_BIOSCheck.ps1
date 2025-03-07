##*=============================================
##* VARIABLE LISTINGS
##*=============================================

$Date = Get-Date -Format 'MMMdd_HHMMttss'

# Application Details - ModIfy Script Details
[string]$appVendor = 'Company'
[string]$appName = 'DellBIOSDiscovery' ## Update Me
[string]$appNameWithSpaces = "Dell BIOS Discovery" ## Update Me
[string]$appVersion = '1.0.0.0' ## Update Me
[string]$appTitle = "$appVendor $appName $appVersion"
[string]$appArch = 'x64x86' ## Update Me (If Needed)
[string]$appLang = 'EN'
[string]$appRevision = '01'
[string]$appScriptVersion = '1.0.0.0' ## Update Me
[string]$appScriptDate = '02/21/2024' ## Update Me
[string]$appScriptAuthor = 'Nathan C. Hoy and Tyler Siniff' ## Update Me
[string]$LogRegKey = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Company-SD"
[string]$runtime = '5'

#region DONOTMODIfY

# Log File Info 
$LogPath = 'C:\Windows\Company-SD\Logs'
$LogName = "$appName" + "_" + "$appScriptVersion" + "_" + "PS.log"
$LogFile = Join-Path -Path $LogPath -ChildPath $LogName

$FolderCheckLeaf = Test-Path -Path $LogPath -PathType Leaf
$FolderCheckContainer = Test-Path -Path $LogPath -PathType Container

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

$FlagSingle = $false
$FlagMultiple = $false
$MultipleCount = 0

#*=============================================
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

Function Get-DellCatalogPC
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateSet('Application', 'BIOS', 'Driver', 'Firmware')]
        [string]$Component,
        [Parameter(Mandatory = $false, Position = 1)]
        [switch]$Compatible
    )
    $VerbosePreference = "Continue"
    
    #=======================================================================
    # Compatibility
    #=======================================================================
    
    $SystemSKU = $((Get-WmiObject -Class Win32_ComputerSystem).SystemSKUNumber).Trim()
    $BIOSVersion = $((Get-WmiObject -Class Win32_BIOS).SMBIOSBIOSVersion).Trim()
    
    #=======================================================================
    # Variables
    #=======================================================================
    $DellDownloadsUrl = "http://downloads.dell.com/"
    $CatalogPcUrl = "http://downloads.dell.com/catalog/CatalogPC.cab"
    
    $DownloadPath = 'C:\Windows\Company-SD\Repo'
    
    $RepoFolderCheckLeaf = Test-Path -Path $DownloadPath -PathType Leaf
    $RepoFolderCheckContainer = Test-Path -Path $DownloadPath -PathType Container
    
    $OfflineCatalogPcFullName = Join-Path 'C:\Windows\Company-SD\Repo' "Get-DellCatalogPC.xml"
    $CatalogPcCabName = [string]($CatalogPcUrl | Split-Path -Leaf)
    $CatalogPcCabFullName = Join-Path $DownloadPath $CatalogPcCabName
    $CatalogPcXmlName = "CatalogPC.xml"
    $CatalogPCXmlFullName = Join-Path $DownloadPath $CatalogPcXmlName
    
    #=======================================================================
    # Offline Catalog
    #=======================================================================
    
    If (($RepoFolderCheckLeaf -eq $true) -or ($RepoFolderCheckContainer -eq $false))
    {
        Remove-Item -Path $DownloadPath -Force -ErrorAction SilentlyContinue | Out-Null
        New-Item -ItemType Directory -Path $DownloadPath -Force | Out-Null;
        
        $RepoFolderCheckLeaf = Test-Path -Path $LogPath -PathType Leaf
        $RepoFolderCheckContainer = Test-Path -Path $LogPath -PathType Container
    }
    
    If ($RepoFolderCheckContainer -eq $true)
    {
        Add-Content -Path $LogFile "                                                               Driver CAB"
        Add-Content -Path $LogFile "***************************************************************************************************"
        
        If (Test-Path $OfflineCatalogPcFullName)
        {
            $ExistingFile = Get-Item $OfflineCatalogPcFullName
            
            If (((Get-Date) - $ExistingFile.CreationTime).TotalDays -gt 14)
            {
                Add-Content -Path $LogFile "Removing previous Offline Catalog"
                Remove-Item -Path $OfflineCatalogPcFullName -Force -ErrorAction SilentlyContinue
            }
        }
        
        If (Test-Path $OfflineCatalogPcFullName)
        {
            Add-Content -Path $LogFile "Importing Offline Catalog = [$OfflineCatalogPcFullName]"
            $DellCatalogPc = Import-Clixml -Path $OfflineCatalogPcFullName
        }
        Else
        {
            If (Test-Path $CatalogPcCabFullName)
            {
                $ExistingFile = Get-Item $CatalogPcCabFullName
                
                If (((Get-Date) - $ExistingFile.CreationTime).TotalDays -gt 1)
                {
                    Add-Content -Path $LogFile "Removing Previously Downloading = [$CatalogPcCabName]"
                    Remove-Item -Path $CatalogPcCabFullName -Force -ErrorAction SilentlyContinue
                }
            }
            
            If (-NOT (Test-Path $CatalogPcCabFullName))
            {
                Add-Content -Path $LogFile "Downloading the Dell Update Catalog = [$CatalogPcUrl]"
                Add-Content -Path $LogFile "Saving Dell Update Catalog = [$CatalogPcCabFullName]"
                
                (New-Object System.Net.WebClient).DownloadFile($CatalogPcUrl, "$CatalogPcCabFullName")
            }
            
            If (-NOT (Test-Path $CatalogPcCabFullName))
            {
                Write-PoShLog "[ERROR] Could not download the Dell CatalogPC.cab"
                Break
            }
            
            Add-Content -Path $LogFile "Extracting Dell Update Catalog"
            
            Expand "$CatalogPcCabFullName" "$CatalogPCXmlFullName" | Out-Null
            
            If (-NOT (Test-Path $CatalogPCXmlFullName))
            {
                Add-Content -Path $LogFile "Could Not Expand the Dell CatalogPC.xml"
                
                Break
            }
            
            Add-Content -Path $LogFile "Analyzing the Dell Update Catalog = [$CatalogPCXmlFullName]"
            
            [xml]$XMLCatalogPcUrl = Get-Content "$CatalogPCXmlFullName" -ErrorAction Stop
            
            Add-Content -Path $LogFile "Loading the Dell Update XML Nodes"
            
            $DellCatalogPc = $XMLCatalogPcUrl.ManIfest.SoftwareComponent
            
            $DellCatalogPc = $DellCatalogPc | `
            Select-Object @{ Label = "Component"; Expression = { ($_.ComponentType.Display.'#cdata-section'.Trim()) }; },
                          @{ Label = "ReleaseDate"; Expression = { [datetime] ($_.dateTime) }; },
                          @{ Label = "Name"; Expression = { ($_.Name.Display.'#cdata-section'.Trim()) }; },
                          #@{Label="Description";Expression={($_.Description.Display.'#cdata-section'.Trim())};},
                          @{ Label = "DellVersion"; Expression = { $_.dellVersion }; },
                          @{ Label = "Url"; Expression = { -join ($DellDownloadsUrl, $_.path) }; },
                          @{ Label = "VendorVersion"; Expression = { $_.vendorVersion }; },
                          @{ Label = "Criticality"; Expression = { ($_.Criticality.Display.'#cdata-section'.Trim()) }; },
                          @{ Label = "FileName"; Expression = { (split-path -leaf $_.path) }; },
                          @{ Label = "SizeMB"; Expression = { '{0:f2}' -f ($_.size/1MB) }; },
                          @{ Label = "PackageID"; Expression = { $_.packageID }; },
                          @{ Label = "PackageType"; Expression = { $_.packageType }; },
                          @{ Label = "ReleaseID"; Expression = { $_.ReleaseID }; },
                          @{ Label = "Category"; Expression = { ($_.Category.Display.'#cdata-section'.Trim()) }; },
                          @{ Label = "SupportedDevices"; Expression = { ($_.SupportedDevices.Device.Display.'#cdata-section'.Trim()) }; },
                          @{ Label = "SupportedBrand"; Expression = { ($_.SupportedSystems.Brand.Display.'#cdata-section'.Trim()) }; },
                          @{ Label = "SupportedModel"; Expression = { ($_.SupportedSystems.Brand.Model.Display.'#cdata-section'.Trim()) }; },
                          @{ Label = "SupportedSystemID"; Expression = { ($_.SupportedSystems.Brand.Model.systemID) }; },
                          @{ Label = "SupportedOperatingSystems"; Expression = { ($_.SupportedOperatingSystems.OperatingSystem.Display.'#cdata-section'.Trim()) }; },
                          @{ Label = "SupportedArchitecture"; Expression = { ($_.SupportedOperatingSystems.OperatingSystem.osArch) }; },
                          @{ Label = "HashMD5"; Expression = { $_.HashMD5 }; }
            
            Add-Content -Path $LogFile "Exporting Offline Catalog = [$OfflineCatalogPcFullName]"
            
            $DellCatalogPc = $DellCatalogPc | Sort-Object ReleaseDate -Descending
            $DellCatalogPc | Export-Clixml -Path $OfflineCatalogPcFullName
        }
        #=======================================================================
        # Filter Compatible
        #=======================================================================
        
        If ($Compatible)
        {
            Add-Content -Path $LogFile "Filtering XML for Compatible SystemSKU =  [$SystemSKU]"
            $DellCatalogPc = $DellCatalogPc | Where-Object { $_.SupportedSystemID -contains $SystemSKU }
        }
        
        #=======================================================================
        # Filter Component
        #=======================================================================
        If ($Component)
        {
            Add-Content -Path $LogFile "Filtering XML for Limited Scope =  [$Component]"
            $DellCatalogPc = $DellCatalogPc | Where-Object { $_.Component -eq $Component }
        }
        
        $DellCatalogPc
    }
}

##*=============================================
##* END FUNCTION LISTINGS
##*=============================================

##*=============================================
##* SCRIPT BODY
##*=============================================

#*===============================================
##* PRE-INSTALLATION
##*===============================================

#=======================================================================
# Remove Current Log File If Bigger Than 50 MB
#=======================================================================

If (($FolderCheckLeaf -eq $true) -or ($FolderCheckContainer -eq $false))
{
    Remove-Item -Path $LogPath -Force -ErrorAction SilentlyContinue | Out-Null
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null;
    
    $FolderCheckLeaf = Test-Path -Path $LogPath -PathType Leaf
    $FolderCheckContainer = Test-Path -Path $LogPath -PathType Container
}

#*================================================
##* END PRE-INSTALLATION
##*===============================================

#*================================================
##* INSTALLATION
##*===============================================

If ($FolderCheckContainer -eq $true)
{
    #=======================================================================
    # Remove Previous Log (If Needed)
    #=======================================================================
    
    If (Get-Item -Path "$LogFile" -ErrorAction SilentlyContinue | Where-Object $_.length -gt 50mb)
    {
        Remove-Item -Path "$LogFile" -Force -ErrorAction SilentlyContinue
    }
    
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
    
    If (Test-Path -Path $LogPath)
    {
        #=======================================================================
        # Gather Driver and Software Results
        #=======================================================================
        
        $BIOSresults = Get-DellCatalogPC -Compatible -Component BIOS
        
        #region Log Results
        
        If ($BIOSresults.Component.Count -eq 1)
        {
            $FlagSingle = $true
            
            Add-Content -Path $LogFile "***************************************************************************************************"
            Add-Content -Path $LogFile "                                                               Driver Details | 1 of 1"
            Add-Content -Path $LogFile "***************************************************************************************************"
            ForEach ($item in $BIOSresults.PSObject.Get_Properties())
            {
                $Name = $($item).Name
                $Value = $($item).Value
                Add-Content -Path $LogFile "$Name = [$Value]"
            }
            
            Add-Content -Path $LogFile "***************************************************************************************************"
            
        }
        ElseIf ($BIOSresults.Component.Count -gt 1)
        {
            $FlagMultiple = $true
            
            Add-Content -Path $LogFile "***************************************************************************************************"
            
            ForEach ($item in $BIOSresults)
            {
                $MultipleCount++
                Add-Content -Path $LogFile "                                                               Driver Details | $MultipleCount of $($BIOSresults.Component.Count)"
                Add-Content -Path $LogFile "***************************************************************************************************"
                
                ForEach ($subitem in $item.PSObject.Get_Properties())
                {
                    $Name = $($subitem).Name
                    $Value = $($subitem).Value
                    Add-Content -Path $LogFile "$Name = [$Value]"
                }
                
                Add-Content -Path $LogFile "***************************************************************************************************"
            }
        }
        
        #endregion
        
        #region Tattoo Results 
        
        #=======================================================================
        # Single Update
        #=======================================================================
        
        If ($FlagSingle -eq $true)
        {
            If ($BIOSresults.VendorVersion)
            {
                If ([version]$BIOsVerison -ge [version]$($BIOSresults.VendorVersion))
                {
                    $BIOsCurrent = "Yes"
                }
                Else
                {
                    $BIOsCurrent = "No"
                }
                
                Set-ItemProperty "$LogRegKey\$appVendorfinal\$appnamefinal\$appVer" -Name "BIOSsystem" -Value "$BIOsVerison" -Force
                Set-ItemProperty "$LogRegKey\$appVendorfinal\$appnamefinal\$appVer" -Name "BIOScurrent" -Value "$BIOsCurrent" -Force
                Set-ItemProperty "$LogRegKey\$appVendorfinal\$appnamefinal\$appVer" -Name "BIOSavailable" -Value "$($BIOSresults.VendorVersion)" -Force
                Set-ItemProperty "$LogRegKey\$appVendorfinal\$appnamefinal\$appVer" -Name "BIOSreleasedate" -Value "$($BIOSresults.ReleaseDate)" -Force
                Set-ItemProperty "$LogRegKey\$appVendorfinal\$appnamefinal\$appVer" -Name "BIOSurl" -Value "$($BIOSresults.Url)" -Force
                Set-ItemProperty "$LogRegKey\$appVendorfinal\$appnamefinal\$appVer" -Name "EndTime" -Value "$(Get-Date)" -Force
                Set-ItemProperty "$LogRegKey\$appVendorfinal\$appnamefinal\$appVer" -Name "Installed" -Value "0" -Force
            }
            Else
            {
                Set-ItemProperty "$LogRegKey\$appVendorfinal\$appnamefinal\$appVer" -Name "BIOSsystem" -Value "$BIOsVerison" -Force
                Set-ItemProperty "$LogRegKey\$appVendorfinal\$appnamefinal\$appVer" -Name "BIOScurrent" -Value "Unknown" -Force
                Set-ItemProperty "$LogRegKey\$appVendorfinal\$appnamefinal\$appVer" -Name "BIOSavailable" -Value "Unknown" -Force
                Set-ItemProperty "$LogRegKey\$appVendorfinal\$appnamefinal\$appVer" -Name "BIOSreleasedate" -Value "Unknown" -Force
                Set-ItemProperty "$LogRegKey\$appVendorfinal\$appnamefinal\$appVer" -Name "BIOSurl" -Value "Unknown" -Force
                Set-ItemProperty "$LogRegKey\$appVendorfinal\$appnamefinal\$appVer" -Name "EndTime" -Value "$(Get-Date)" -Force
                Set-ItemProperty "$LogRegKey\$appVendorfinal\$appnamefinal\$appVer" -Name "Installed" -Value "1" -Force
            }
        }
        
        #=======================================================================
        # Multiple - Search for Latest
        #=======================================================================
        
        ElseIf ($FlagMultiple -eq $true)
        {
            $Sort = $BIOSresults | Sort-Object -Property ReleaseDate -Descending
            
            $MostRecent = $Sort[0]
            
            If ([version]$BIOsVerison -ge [version]$($MostRecent.VendorVersion))
            {
                $BIOsCurrent = "Yes"
            }
            Else
            {
                $BIOsCurrent = "No"
            }
            
            Set-ItemProperty "$LogRegKey\$appVendorfinal\$appnamefinal\$appVer" -Name "BIOSsystem" -Value "$BIOsVerison" -Force
            Set-ItemProperty "$LogRegKey\$appVendorfinal\$appnamefinal\$appVer" -Name "BIOScurrent" -Value "$BIOsCurrent" -Force
            Set-ItemProperty "$LogRegKey\$appVendorfinal\$appnamefinal\$appVer" -Name "BIOSavailable" -Value "$($MostRecent.VendorVersion)" -Force
            Set-ItemProperty "$LogRegKey\$appVendorfinal\$appnamefinal\$appVer" -Name "BIOSreleasedate" -Value "$($MostRecent.ReleaseDate)" -Force
            Set-ItemProperty "$LogRegKey\$appVendorfinal\$appnamefinal\$appVer" -Name "BIOSurl" -Value "$($MostRecent.Url)" -Force
            Set-ItemProperty "$LogRegKey\$appVendorfinal\$appnamefinal\$appVer" -Name "EndTime" -Value "$(Get-Date)" -Force
            Set-ItemProperty "$LogRegKey\$appVendorfinal\$appnamefinal\$appVer" -Name "Installed" -Value "0" -Force
        }
        
        #endregion
    }
    Else
    {
        ## Failed to Start Log - No Actions Performed
        
        Set-ItemProperty "$LogRegKey\$appVendorfinal\$appnamefinal\$appVer" -Name "BIOSsystem" -Value "Unknown" -Force
        Set-ItemProperty "$LogRegKey\$appVendorfinal\$appnamefinal\$appVer" -Name "BIOScurrent" -Value "Unknown" -Force
        Set-ItemProperty "$LogRegKey\$appVendorfinal\$appnamefinal\$appVer" -Name "BIOSavailable" -Value "Unknown" -Force
        Set-ItemProperty "$LogRegKey\$appVendorfinal\$appnamefinal\$appVer" -Name "BIOSreleasedate" -Value "Unknown" -Force
        Set-ItemProperty "$LogRegKey\$appVendorfinal\$appnamefinal\$appVer" -Name "BIOSurl" -Value "Unknown" -Force
        Set-ItemProperty "$LogRegKey\$appVendorfinal\$appnamefinal\$appVer" -Name "EndTime" -Value "$(Get-Date)" -Force
        Set-ItemProperty "$LogRegKey\$appVendorfinal\$appnamefinal\$appVer" -Name "Installed" -Value "1" -Force
    }
    
    Stop-Log -LogPath $LogFile
    [Environment]::Exit
}

#*================================================
##* END INSTALLATION
##*===============================================

##*=============================================
##* END SCRIPT BODY
##*=============================================