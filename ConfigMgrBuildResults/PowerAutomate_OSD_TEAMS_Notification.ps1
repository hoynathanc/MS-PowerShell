﻿$List = Get-ChildItem -Path \\FileShare\BuildResults -Recurse
$URI = "https://example.com/example"
$json_array = @()
$json_body =""

If ($List.Count -ne 0)
{
	
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
        $Agency = $($DeviceInfo_Json)[9]
		
		$json_body = ConvertTo-Json -Depth 4 @{
			
			value = @(
				@{
					HostName  = "$HostName"
					MakeModel = "$MakeModel"
					OS	      = "$OS"
					OSVersion = "$OSVersion"
					SN	      = "$SN"
					BIOS	  = "$BIOS"
					RunTime   = "$RunTime"
					BuiltBy   = "$BuiltBy"
                    Agency    = "$Agency"
				}
				
			)
		}
		
	}
Else
{
    ForEach ($File in $List)
    {
        $DeviceInfo_Json = Get-Content -Path $File.FullName
        
        $HostName = $($DeviceInfo_Json)[0]
        $MakeModel = $($DeviceInfo_Json)[2]
        $OS = $($DeviceInfo_Json)[3]
        $OSVersion = $($DeviceInfo_Json)[4]
        $SN = $($DeviceInfo_Json)[5]
        $BIOS = $($DeviceInfo_Json)[6]
        $RunTime = $($DeviceInfo_Json)[7]
        $BuiltBy = $($DeviceInfo_Json)[8]
        $Agency = $($DeviceInfo_Json)[9]
        
        $json_object = @{
            HostName  = "$HostName"
            MakeModel = "$MakeModel"
            OS        = "$OS"
            OSVersion = "$OSVersion"
            SN        = "$SN"
            BIOS      = "$BIOS"
            RunTime   = "$RunTime"
            BuiltBy   = "$BuiltBy"
            Agency    = "$Agency"
        }
        
        $json_array += $json_object
    }

    $json_body = @{
        value = $json_array
    } | ConvertTo-Json -Depth 4
}
}


###################
## Post to Teams ##
###################

If ($List.Count -eq 1)
{
	Invoke-RestMethod -uri $URI -Method Post -body $json_body -ContentType 'application/json' -ErrorAction SilentlyContinue
}
ElseIf ($List.Count -gt 1)
{
	Invoke-RestMethod -uri $URI -Method Post -body $json_body -ContentType 'application/json' -ErrorAction SilentlyContinue
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