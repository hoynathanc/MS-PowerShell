$Date = Get-Date -Format 'MMMdd_HHMMttss'

$FileShares = @(
    "\\example_server1\path1\folder",
    "\\example_server2\path2\folder"
)

## Generate New Folder for Scans with Current Date and Time

New-Item -Path "\\path\path\Network Scan Details\$Date" -ItemType Directory -Force

ForEach ($Share in $FileShares)
{
    ## Generate New Folder for Scans for Each File Share
    
    $ValidFolderName = $Share.Replace("\\", "").Replace("$", "").Replace("\", "_")
    New-Item -Path "\\path\path\$Date\$ValidFolderName" -ItemType Directory
    
    ## Perform Scan
    
    $LogPath = "\\path\path\Network Scan Details\$Date\$ValidFolderName\Log"
    $ConfigPath = "\\path\path\Network Scan Details\$Date\$ValidFolderName\Config"
    
    $cmdPath = "\\path\PSTCollectionTool\DataCollectorMaster\DataCollectorMaster.exe"
    $cmdArgList = @(
        "-DataSource", "PST",
        "-Mode", "Find"
        "-JobName", "$ValidFolderName"
        "-Locations", "$Share"
        "-LogLocation", "$LogPath"
        "-ConfigurationLocation", "$ConfigPath"
    )
    
    & $cmdPath $cmdArgList
}