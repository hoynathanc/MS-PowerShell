$List = Get-ChildItem -Path \\FileShare\BuildResults -Recurse
$URI = "https://example.com/example"

If ($List.Count -ne 0)
{
    #############################
    ## BUILD RESULTS DISCOVERY ##
    #############################
    
    $Table = @()
    
    ForEach ($Computer in $List) ## Filter Through Files
    {
        
        $DeviceInfo = Get-Content -Path $Computer.FullName
        
        $item = New-Object PSObject
        $item | Add-Member -type NoteProperty -Name 'Computer Name' -Value $($DeviceInfo)[0]
        $item | Add-Member -type NoteProperty -Name 'Make and Model' -Value $($DeviceInfo)[2]
        $item | Add-Member -type NoteProperty -Name 'Operating System' -Value $($DeviceInfo)[3]
        $item | Add-Member -type NoteProperty -Name 'OS Version' -Value $($DeviceInfo)[4]
        $item | Add-Member -type NoteProperty -Name 'Serial Number' -Value $($DeviceInfo)[5]
        $item | Add-Member -type NoteProperty -Name 'BIOS Version' -Value $($DeviceInfo)[6]
        $item | Add-Member -type NoteProperty -Name 'Run Time' -Value $($DeviceInfo)[7]
        $item | Add-Member -type NoteProperty -Name 'Built By' -Value $($DeviceInfo)[8]
        
        $Table += $item
    }
    
    $Header = @"
        <style>
        TABLE {border-width: 1px; border-style: solid; border-color: black; border-collapse: collapse;}
        TH {border-width: 1px; padding: 3px; border-style: solid; border-color: black; background-color: #6495ED;}
        TD {border-width: 1px; padding: 3px; border-style: solid; border-color: black;}
        </style>
"@
    
    $Body = $Table | ConvertTo-Html
    $JSON_Multiple = $Table | ForEach { "$_<br>" }
    
    ##################
    ## JSON SECTION ##
    ##################
    
    If ($List.Count -eq 1)
    {
        $DeviceInfo_Json = Get-Content -Path $List.FullName
        
        $HostName = $($DeviceInfo_Json)[0]
        $MakeModel = $($DeviceInfo_Json)[2]
        $OS = $($DeviceInfo_Json)[3]
        $OSVersion = $($DeviceInfo_Json)[4]
        $SN = $($DeviceInfo_Json)[5]
        $BIOS = $($DeviceInfo_Json)[6]
        $RunTime = $($DeviceInfo_Json)[7]
        $BuiltBy = $($DeviceInfo_Json)[8]
        
        $json_body = ConvertTo-Json -Depth 4 @{
            title      = "OSD Build Results - Within Last 15 Minutes"
            themeColor = "ff1717"
            text       = " "
            sections   = @(
                @{
                    activityTitle    = 'OSD Complete'
                    activitySubtitle = "$HostName"
                    activityImage    = $logo
                },
                @{
                    title = 'Detailed Information'
                    facts = @(
                        @{
                            name  = 'Make and Model'
                            value = "$MakeModel"
                            
                        },
                        @{
                            name  = 'Operating System'
                            value = "$OS"
                            
                        },
                        @{
                            name  = 'OS Version'
                            value = "$OSVersion"
                            
                        },
                        @{
                            name  = 'Serial Number'
                            value = "$SN"
                            
                        },
                        @{
                            name  = 'BIOS Version'
                            value = "$BIOS"
                            
                        },
                        @{
                            name  = 'Run Time'
                            value = "$RunTime"
                        },
                        @{
                            name  = 'Built By'
                            value = "$BuiltBy"
                        }
                    )
                }
            )
        }
    }
    Else
    {
        ## Multiple Devices
    }
    
    ###########################
    ## Send to PowerAutomate ##
    ###########################
    
    If ($List.Count -eq 1)
    {
        Invoke-RestMethod -uri $URI -Method Post -body $json_body -ContentType 'application/json' -ErrorAction SilentlyContinue
    }
    Else
    {
        Invoke-RestMethod -uri $URI -Method Post -body "{'title': 'OSD Build Results - Within Last 15 Minutes', 'activityTitle': 'OSD Complete', 'themeColor': 'ff1717',  'text': '$Body'}" -ContentType 'application/json' -ErrorAction SilentlyContinue
    }
    #####################
    ## Cleanup Actions ##
    #####################
    
    If ($List.Count -eq 1)
    {
        Remove-Item -Path $List.FullName -Force
    }
    Else
    {
        ForEach ($File in $List)
        {
            Remove-Item -Path $File.FullName -Force
        }
    }
}
Else
{
    ## Bypass Sending Report
}