function LogToFile {
    <#
    .SYNOPSIS
        Log to file

    .DESCRIPTION
        Log data to disk

    .PARAMETER DataToLog
        Object to log to disk

    .PARAMETER FileType
        Type of file we are outputting

    .PARAMETER OutputDirectory
        Directory to write data

    .PARAMETER Outputfile
        Log file name

    .EXAMPLE
        None
    #>

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param(
        [PSCustomObject]
        $DataToLog,

        [string]
        $FileType,

        [Parameter(Position = 0)]
        [string]
        $OutputDirectory,

        [Parameter(Position = 1)]
        [string]
        $Outputfile
    )

    try {
        switch ($FileType) {
            'txt' {
                $DataToLog | Out-File -FilePath (Join-Path -Path $OutputDirectory -ChildPath $Outputfile) -Encoding utf8
            }

            'csv' {
                [PSCustomObject]$DataToLog | Sort-Object | Export-Csv -Path (Join-Path -Path $OutputDirectory -ChildPath $Outputfile) -Encoding utf8 -NoTypeInformation -Append -ErrorAction Stop
            }
        }
    }
    catch {
        $_
        return
    }
}

function Get-CompliancePolicyCount {
    <#
	.SYNOPSIS
		Calculate compliance policies

	.DESCRIPTION
		Calculate total number of O365 tenant wide compliance related policies

	.PARAMETER EnableDebugLogging
		Enable logging

	.PARAMETER OutputDirectory
        Save location for the data collection

	.PARAMETER OutputFile
		Save file

	.PARAMETER SaveResults
		Switch to indicate saving output to a logging file

	.PARAMETER TranscriptFile
		Logging File

	.PARAMETER UserPrincipalName
		Name of the admin account used to log in to the Exchange and Security and Compliance workloads

    .EXAMPLE
		C:\PS> Get-CompliancePolicyCount -UserPrincipalName admin@tenant.onmicrosoft.com -SaveResults

		Will connect to your tenant as your administrator, query all policy results and save them to disk for review.

	.EXAMPLE
		C:\PS> Get-CompliancePolicyCount -EnableDebugLogging

		Enable debugging logging. Transcript logs will be saved to c:\CompliancePolicyLogging\Transcript.log"

	.EXAMPLE
		C:\PS> Get-CompliancePolicyCount -SaveResults -Verbose

		Query compliance policy information and save the current scan to the default location of c:\CompliancePolicyLogging\PolicyResults.csv

	.NOTES
		1. Limits for Microsoft 365 retention policies and retention label policies - Microsoft Purview (compliance) | Microsoft Docs (https://docs.microsoft.com/en-us/microsoft-365/compliance/retention-limits?view=o365-worldwide)
		2. In-Place holds: https://docs.microsoft.com/en-us/microsoft-365/compliance/identify-a-hold-on-an-exchange-online-mailbox?view=o365-worldwide
		3. eDiscovery API for Microsoft Graph is now generally available - https://devblogs.microsoft.com/microsoft365dev/ediscovery-api-for-microsoft-graph-is-now-generally-available/
	#>

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    [OutputType('System.String')]
    param(
        [switch]
        $EnableDebugLogging,

        [string]
        $OutputDirectory = "c:\CompliancePolicyLogging",

        [string]
        $OutputFile = "CompliancePolicyResults",

        [switch]
        $SaveResults,

        [string]
        $TranscriptFile = "Transcript.txt",

        [string]
        $UserPrincipalName = 'admin@tenant.onmicrosoft.com'
    )

    begin {
        Write-Output "Starting policy evaluation"
        $parameters = $PSBoundParameters
        $connectionErrors = "None"
        $random = Get-Random
        $policyCounter = 0
        $maximumPolicyCount = 10000
        $savedErrorActionPreference = $ErrorActionPreference
        [System.Collections.ArrayList] $inPlaceHoldsList = @()
        [System.Collections.ArrayList] $dlpPolicyList = @()
        [System.Collections.ArrayList] $retentionPolicyList = @()
        [System.Collections.ArrayList] $standardDiscoveryPolicyList = @()
        [System.Collections.ArrayList] $advancedDiscoveryPolicyList = @()
        [System.Collections.ArrayList] $standardDiscoveryPolicyMemberList = @()
        [System.Collections.ArrayList] $advancedDiscoveryPolicyMemberList = @()

        try {
            if ($parameters.ContainsKey('EnableDebugLogging')) {
                Write-Verbose "Starting debug logging"
                Start-Transcript -Path (Join-Path -Path $OutputDirectory -ChildPath $TranscriptFile) -Append
            }
        }
        catch {
            Write-Output "ERROR: $_"
        }

        Write-Verbose "Saving current ErrorActionPreference of $savedErrorActionPreference and changing to 'Stop'"
        $ErrorActionPreference = 'Stop'

        if ($UserPrincipalName -eq 'admin@tenant.onmicrosoft.com') { $UserPrincipalName = Read-Host -Prompt "Please enter an admin account" }

        try {
            Write-Verbose "Checking for the ExchangeOnlineManagement module"
            if (-NOT (Get-Module -Name ExchangeOnlineManagement -ListAvailable)) {
                Write-Verbose "Installing the ExchangeOnlineManagement module from the PowerShellGallery"
                if (Install-Module -Name ExchangeOnlineManagement -Repository PSGallery -Scope CurrentUser -Force) {
                    Write-Verbose "Importing the ExchangeOnlineManagement"
                    Import-Module -Name ExchangeOnlineManagement -Force
                }
            }
            else {
                Write-Verbose "ExchangeOnlineManagement found. Importing module"
                Import-Module -Name ExchangeOnlineManagement -Force
            }
        }
        catch {
            Write-Output "ERROR: $_"
            return
        }

        try {
            Write-Verbose "Checking for existence of: $($OutputDirectory)"
            if (-NOT(Test-Path -Path $OutputDirectory)) {
                $null = New-Item -Path $OutputDirectory -ItemType Directory
                Write-Verbose "Created new directory: $($OutputDirectory)"
            }
        }
        catch {
            Write-Output "ERROR: $_"
            return
        }

        try {
            if (Get-ChildItem -Path $OutputDirectory) {
                Compress-Archive -Path $OutputDirectory -DestinationPath "$OutputDirectory\OldFiles-Archive.$(get-date -f yyyy-MM-dd).zip" -Force -CompressionLevel Fastest
                Write-Verbose "Cleaning up and compressing old files for archive"
                Remove-Item -Path $OutputDirectory\"*.*" -Exclude "*.zip"
            }
        }
        catch {
            Write-Output "ERROR: $_"
            return
        }
    }

    process {
        try {
            Write-Output "Connecting to Exchange Online"
            Connect-ExchangeOnline -UserPrincipalName $UserPrincipalName -ShowBanner:$false -ShowProgress:$false -ErrorVariable failedConnection
            Write-Output "Connecting to the Security and Compliance Center"
            Connect-IPPSSession -UserPrincipalName $UserPrincipalName -ErrorVariable FailedConnection
        }
        catch {
            $connectionErrors = $_
            return
        }

        try {
            Write-Verbose "Querying Organization Configuration - In-place Hold Policies"
            if (($orgSettings = Get-OrganizationConfig | Select-Object Name, InPlaceHolds, GUID).InPlaceHolds.Count -ge 1) {
                foreach ($inPlaceHold in $orgSettings.InPlaceHolds) {
                    $policyCounter ++
                    Write-Progress -Activity "Querying Organization Configuration - In-place Hold Policies" -Status "Querying policy #: $progressCounter" -PercentComplete ($progressCounter / $orgSettings.InPlaceHolds.count * 100)
                    $progressCounter ++
                    $null = $inPlaceHoldsList.Add($inPlaceHold)
                }
            }
            else {
                $null = $inPlaceHoldsList.Add("No organizational in-place holds found!")
            }

            # Retention policies in the Microsoft Purview compliance center
            Write-Verbose "Querying $($orgSettings.Name)'s retention polices"
            if (($retentionPolicies = Get-RetentionCompliancePolicy).Count -ge 1) {
                $progressCounter = 1
                foreach ($retentionPolicy in $retentionPolicies) {
                    $policyCounter ++
                    Write-Progress -Activity "Querying $($orgSettings.Name)'s retention polices" -Status "Querying retention policy #: $progressCounter" -PercentComplete ($progressCounter / $retentionPolicies.count * 100)
                    $progressCounter ++
                    $null = $retentionPolicyList.Add($retentionPolicy)
                }
            }
            else {
                $null = $retentionPolicyList.Add("No retention policies found!")
            }

            # Data loss prevention (DLP) policies in the Microsoft Purview compliance center
            Write-Verbose "Querying $($orgSettings.Name)'s DLP Policies"
            if (($dlpPolicies = Get-DlpCompliancePolicy).Count -ge 1) {
                $progressCounter = 1
                foreach ($dlpPolicy in $dlpPolicies) {
                    $policyCounter ++
                    Write-Progress -Activity "Querying $($orgSettings.Name)'s DLP Policies" -Status "Querying DLP policy #: $progressCounter" -PercentComplete ($progressCounter / $dlpPolicies.count * 100)
                    $progressCounter ++
                    $null = $dlpPolicyList.Add($dlpPolicy)
                }
            }
            else {
                $null = $advancedEDiscoveryCasesList.Add("No DLP policies found!")
            }

            # eDiscovery Standard cases in the Microsoft Purview compliance center
            Write-Verbose "Querying $($orgSettings.Name)'s standard eDiscovery cases"
            if (($standardDiscoveryCases = Get-ComplianceCase).Count -ge 1) {
                $progressCounter = 1
                foreach ($standardCase in $standardDiscoveryCases) {
                    $policyCounter ++
                    Write-Progress -Activity "Querying $($orgSettings.Name)'s standard eDiscovery cases" -Status "Querying standard eDiscovery case #: $progressCounter" -PercentComplete ($progressCounter / $standardDiscoveryCases.count * 100)
                    $progressCounter ++
                    $null = $standardDiscoveryPolicyList.Add($standardCase)

                    Write-Verbose "Querying $($orgSettings.Name)'s standard eDiscovery case custodians"
                    if (($caseMembers = Get-ComplianceCaseMember -Case $standardCase.Name).Count -ge 1) {
                        foreach ($caseMember in $caseMembers) {
                            $policyCounter ++

                            $caseMember = [PSCustomObject]@{
                                'Case Name'               = $standardCase.Name
                                'Case Identity'           = $standardCase.Identity
                                'Case Status'             = $standardCase.CaseStatus
                                'Case Type'               = $standardCase.CaseType
                                'Custodian on Hold'       = $caseMember.DisplayName
                                ArchiveGuid               = $caseMember.ArchiveGuid
                                ExternalDirectoryObjectId = $caseMember.ExternalDirectoryObjectId
                                Guid                      = $caseMember.Guid
                                RecipientType             = $caseMember.RecipientType
                                WhenChanged               = $caseMember.WhenChanged
                            }
                            $null = $standardDiscoveryPolicyMemberList.Add($caseMember)
                        }
                    }
                    else {
                        $null = $advancedDiscoveryPolicyMemberList.Add("No standard eDiscovery case members found!")
                    }
                }
            }
            else {
                $null = $standardDiscoveryPolicyList.Add("No standard eDiscovery cases found!")
            }

            # eDiscovery Advanced cases in the Microsoft Purview compliance center
            Write-Verbose "Querying $($orgSettings.Name)'s advanced eDiscovery Cases"
            if (($advancedEDiscoveryCases = Get-ComplianceCase -CaseType Advanced).Count -ge 1) {
                $progressCounter = 1
                foreach ($advancedCase in $advancedEDiscoveryCases) {
                    $policyCounter ++
                    Write-Progress -Activity "Querying $($orgSettings.Name)'s advanced eDiscovery Cases" -Status "Querying advanced eDiscovery case #: $progressCounter" -PercentComplete ($progressCounter / $advancedEDiscoveryCases.count * 100)
                    $progressCounter ++
                    $null = $advancedDiscoveryPolicyList.Add($advancedCase)

                    Write-Verbose "Querying $($orgSettings.Name)'s advanced eDiscovery cases custodians"
                    if ($caseMember = Get-ComplianceCaseMember -Case $advancedCase.Name) {
                        $policyCounter ++

                        $caseMember = [PSCustomObject]@{
                            'Case Name'               = $advancedCase.Name
                            'Case Identity'           = $advancedCase.Identity
                            'Case Status'             = $advancedCase.CaseStatus
                            'Case Type'               = $advancedCase.CaseType
                            'Custodian on Hold'       = $caseMember.DisplayName
                            ArchiveGuid               = $caseMember.ArchiveGuid
                            ExternalDirectoryObjectId = $caseMember.ExternalDirectoryObjectId
                            Guid                      = $caseMember.Guid
                            RecipientType             = $caseMember.RecipientType
                            WhenChanged               = $caseMember.WhenChanged
                        }
                        $null = $advancedDiscoveryPolicyMemberList.Add($caseMember)
                    }
                    else {
                        $null = $advancedDiscoveryPolicyMemberList.Add("No case custodians found!")
                    }
                }
            }
            else {
                $null = $advancedEDiscoveryCasesList.Add("No advanced eDiscovery cases found!")
            }

            # (DLP) policies in the Microsoft Purview compliance portal.
            Write-Verbose "Querying $($orgSettings.Name)'s retention label policies"
            if (($retentionLabels = Get-DlpCompliancePolicy).Count -ge 1) { Write-Verbose "Retention labels found: $($retentionLabels.count)" }
            else { $retentionLabels = "No retention labels found" }

            try {
                Write-Output "Preforming session cleanup to: $($orgSettings.Name)"
                $sessions = Get-PSSession
                foreach ($session in $sessions) {
                    if ($session.ComputerName -like '*compliance*' -or $session.ComputerName -eq 'outlook.office365.com') {
                        Write-Verbose "Removing session: $session.ComputerName"
                        Remove-PSSession $session
                    }
                }
            }
            catch {
                Write-Output "ERROR: $_"
                return
            }

            if ($parameters.ContainsKey('EnableDebugLogging')) {
                Write-Verbose "Stopping debug logging"
                Stop-Transcript
            }

            if ($parameters.ContainsKey('SaveResults')) {
                try {
                    Write-Output "Saving $($orgSettings.Name)'s compliance policy data to: $OutputDirectory"
                    LogToFile -DataToLog $dlpPolicyList -OutputDirectory $OutputDirectory -OutputFile "DlpPolicyList-$random.csv" -FileType 'csv'
                    LogToFile -DataToLog $retentionPolicyList -OutputDirectory $OutputDirectory -OutputFile "RetentionPolicyList-$random.csv" -FileType 'csv'
                    LogToFile -DataToLog $standardDiscoveryPolicyList -OutputDirectory $OutputDirectory -OutputFile "Standard-eDiscoveryPolicyList-$random.csv" -FileType 'csv'
                    LogToFile -DataToLog $standardDiscoveryPolicyMemberList -OutputDirectory $OutputDirectory -OutputFile "Standard-eDiscoveryPolicyMemberList-$random.csv" -FileType 'csv'
                    LogToFile -DataToLog $advancedDiscoveryPolicyList -OutputDirectory $OutputDirectory -OutputFile "Advanced-eDiscoveryPolicyList-$random.csv" -FileType 'csv'
                    LogToFile -DataToLog $advancedDiscoveryPolicyMemberList -OutputDirectory $OutputDirectory -OutputFile "Advanced-eDiscoveryCaseMemberList-$random.csv" -FileType 'csv'

                    foreach ($hold in $inPlaceHoldsList) {
                        $holdResults = (($hold -split '(mbx|grp|skp|:|cld|UniH)') -match '\S')

                        switch ($holdResults[0]) {
                            'UniH' { $prefixDescription = 'eDiscovery cases (holds) in the Security and Compliance Center' }
                            'cld' { $prefixDescription = 'Exchange mailbox specific hold (in-place hold)' }
                            'mbx' { $prefixDescription = 'Organization-wide retention policies applied to Exchange mailboxes, Exchange public folders, and 1xN chats in Microsoft Teams. Note 1xN chats are stored in the mailbox of the individual chat participants.' }
                            'grp' { $prefixDescription = 'Organization-wide retention policies applied to Office 365 groups and channel messages in Microsoft Teams.' }
                            'skp' { $prefixDescription = 'Indicates that the retention policy is configured to hold items and then delete them after the retention period expires.' }
                        }

                        switch ($holdResults[3]) {
                            1 { $retentionActionValueDescription = 'Indicates that the retention policy is configured to delete items. The policy does not retain items.' }
                            2 { $retentionActionValueDescription = 'Indicates that the retention policy is configured to hold items. The policy does not delete items after the retention period expires.' }
                            3 { $retentionActionValueDescription = 'Indicates that the retention policy is configured to hold items and then delete them after the retention period expires.' }
                        }

                        $inPlaceHoldsCustom = [PSCustomObject]@{
                            Prefix                     = $holdResults[0]
                            PrefixDescription          = $prefixDescription
                            GUID                       = $holdResults[1]
                            RetentionAction            = $holdResults[3]
                            RetentionActionDescription = $retentionActionValueDescription
                        }
                        LogToFile -DataToLog $inPlaceHoldsCustom -OutputDirectory $OutputDirectory -OutputFile "InPlaceHolds-$random.csv" -FileType 'csv'
                        LogToFile -DataToLog $output -OutputDirectory $OutputDirectory -Outputfile "TotalPolicyCount.txt" -FileType 'txt'
                        Write-Output "Saving policy count data to: $OutputDirectory\$policyCountLogFile"
                    }
                }
                catch {
                    Write-Output "ERROR: $_"
                    return
                }
            }
        }
        catch {
            Write-Output "ERROR: $_"
        }
    }

    end {
        Write-Verbose "Reverting ErrorActionPreference of 'Stop' to $savedErrorActionPreference"
        $ErrorActionPreference = $savedErrorActionPreference
        if ($failedConnection) {
            "CONNECTION FAILURE! Unable to connect to Exchange or the Security and Compliance endpoint. Please check the connection log for more information"
            LogToFile -DataToLog $connectionErrors -OutputDirectory $OutputDirectory -OutputFile "ConnectionLog-$random.txt" -FileType 'txt'
        }
        elseif ($orgSettings.Name) { Write-Output "Compliance policy evaluation of $($orgSettings.Name) completed!" }
        else { Write-Output "Compliance policy evaluation completed!" }

        if ($policyCounter -ge $maximumPolicyCount) {
            $output = "The $($orgSettings.Name) tenant has $policyCounter compliance policies! This exceeds the $maximumPolicyCount policies limit - ERROR! (OVER LIMIT)"
            Write-Output $output
        }
        else {
            $output = "The $($orgSettings.Name) tenant has $policyCounter compliance policies and is under the maximum number of $maximumPolicyCount - OK (UNDER LIMIT)"
            Write-Output $output
        }
    }
}
