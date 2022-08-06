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

	.PARAMETER SaveScanToDisk
		Switch to indicate saving output to a logging file

	.PARAMETER TranscriptFile
		Logging File

	.PARAMETER UserPrincipalName
		Name of the admin account used to log in to the Exchange and Security and Compliance workloads

	.EXAMPLE
		C:\PS> Get-CompliancePolicyCount -EnableDebugLogging

		Enable debugging logging. Transcript logs will be saved to c:\PolicyLogging\Transcript.log"

	.EXAMPLE
		C:\PS> Get-CompliancePolicyCount -UserPrincipalName admin@tenant.onmicrosoft.com

		Logs in to both Exchange online and the Security and Compliance workloads to pull compliance policy information

	.EXAMPLE
		C:\PS> Get-CompliancePolicyCount -SaveScanToDisk -Verbose

		Save the current scan to the default location of c:\PolicyLogging\PolicyResults.csv

	.NOTES
		1. Limits for Microsoft 365 retention policies and retention label policies - Microsoft Purview (compliance) | Microsoft Docs (https://docs.microsoft.com/en-us/microsoft-365/compliance/retention-limits?view=o365-worldwide)
		2. In-Place holds: https://docs.microsoft.com/en-us/microsoft-365/compliance/identify-a-hold-on-an-exchange-online-mailbox?view=o365-worldwide
		3. eDiscovery API for Microsoft Graph is now generally available - https://devblogs.microsoft.com/microsoft365dev/ediscovery-api-for-microsoft-graph-is-now-generally-available/
	#>

    [CmdletBinding()]
    param(
        [switch]
        $EnableDebugLogging,

        [string]
        $OutputDirectory = "c:\PolicyLogging",

        [string]
        $OutputFile = "PolicyResults",

        [switch]
        $SaveScanToDisk,

        [string]
        $TranscriptFile = "Transcript.log",

        [string]
        $UserPrincipalName = 'admin@tenant.onmicrosoft.com'
    )

    begin {
        Write-Output "Starting policy evaluation"
        $parameters = $PSBoundParameters
        $policyCounter = 0
        $maximumPolicyCount = 10000
        [System.Collections.ArrayList] $inPlaceHoldsList = @()
        [System.Collections.ArrayList] $retentionPolicyList = @()
        [System.Collections.ArrayList] $standardDiscoveryPolicyList = @()
        [System.Collections.ArrayList] $advancedDiscoveryPolicyList = @()

        $savedErrorActionPreference = $ErrorActionPreference
        Write-Verbose "Saving current ErrorActionPreference of $savedErrorActionPreference and changing to 'Stop'"
        $ErrorActionPreference = 'Stop'

        try {
            if ($parameters.ContainsKey('EnableDebugLogging')) {
                Write-Verbose "Starting debug logging"
                Start-Transcript -Path (Join-Path -Path $OutputDirectory -ChildPath $TranscriptFile) -Append
            }
        }
        catch {
            Write-Output "ERROR: $_"
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
        }
    }

    process {
        try {
            Write-Output "Connecting to Exchange Online and the Security and Compliance Center"
            Connect-ExchangeOnline -UserPrincipalName $UserPrincipalName -ShowBanner:$false -ShowProgress:$false
            Connect-IPPSSession -UserPrincipalName $UserPrincipalName
            Write-Verbose "Querying Organization Configuration - In-place Hold Policies"
            $orgSettings = Get-OrganizationConfig | Select-Object InPlaceHolds, GUID
            foreach ($inPlaceHold in $orgSettings.InPlaceHolds) {
                $policyCounter ++
                $null = $inPlaceHoldsList.Add($inPlaceHold)
            }

            Write-Verbose "Querying retention polices"
            # Retention policies in the Microsoft Purview compliance center
            $retentionPolicies = Get-RetentionCompliancePolicy
            foreach ($retentionPolicy in $retentionPolicies) {
                $policyCounter ++
                $null = $retentionPolicyList.Add($retentionPolicy)
            }

            Write-Verbose "Querying standard eDiscovery cases"
            # eDiscovery Standard cases in the Microsoft Purview compliance center
            $standardDiscoveryCases = Get-ComplianceCase
            foreach ($standardCase in $standardDiscoveryCases) {
                $policyCounter ++
                $null = $standardDiscoveryPolicyList.Add($standardCase)
                #Get-CaseHoldPolicy -Case $standardCase.Name
                if (Get-ComplianceCaseMember -Case $standardCase.Name) {
                    $policyCounter ++
                }
            }

            Write-Verbose "Querying advanced eDiscovery Cases"
            # eDiscovery Advanced cases in the Microsoft Purview compliance center
            $advancedEDiscoveryCases = Get-ComplianceCase -CaseType Advanced
            foreach ($advancedCase in $advancedEDiscoveryCases) {
                $policyCounter ++
                # Case hold policies in the Microsoft Purview compliance center
                #Get-CaseHoldPolicy -Case $advancedCase.Name
                $null = $advancedDiscoveryPolicyList.Add($advancedCase)
                if (Get-ComplianceCaseMember -Case $standardCase.Name) {
                    $policyCounter ++
                }
            }

            Write-Verbose "Querying retention label policies"
            $retentionLabels = Get-DlpCompliancePolicy # (DLP) policies in the Microsoft Purview compliance portal.
            Write-Verbose "Retention labels found: $($retentionLabels.count)"

            if ($policyCounter -gt $maximumPolicyCount) {
                $output = "WARNING: The number of policies in your tenant are: $policyCounter. This exceeds the maximum number of policies allowed which is: $maximumPolicyCount"
                Write-Output $output

            }
            else {
                $output = "Your tenant has $policyCounter compliance policies which is under the maximum number of policies allowed which is: $maximumPolicyCount"
                Write-Output $output
            }

            try {
                Write-Output "Preforming session cleanup"
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

            # Save policy count
            try {
                $policyCountLogFile = $env:COMPUTERNAME + '-' + "PolicyCount.txt"
                $output | Out-File -FilePath (Join-Path -Path $OutputDirectory -ChildPath $policyCountLogFile) -Encoding utf8
                Write-Output "Saving policy count data to: $OutputDirectory\$policyCountLogFile"
            }
            catch {
                Write-Output "ERROR: $_"
                return
            }

            if ($parameters.ContainsKey('SaveScanToDisk')) {
                try {
                    Write-Output "Saving policy data to: $OutputDirectory"
                    [PSCustomObject]$retentionPolicyList | Sort-Object | Export-Csv -Path (Join-Path -Path $OutputDirectory -ChildPath 'RetentionPolicyList.csv') -Encoding utf8 -NoTypeInformation
                    [PSCustomObject]$standardDiscoveryPolicies | Sort-Object | Export-Csv -Path (Join-Path -Path $OutputDirectory -ChildPath 'StandardDiscoveryPolicies.csv') -Encoding utf8 -NoTypeInformation
                    [PSCustomObject]$advancedDiscoveryPolicies | Sort-Object | Export-Csv -Path (Join-Path -Path $OutputDirectory -ChildPath 'AdvancedDiscoveryPolicies.csv') -Encoding utf8 -NoTypeInformation

                    foreach ($hold in $inPlaceHoldsList) {
                        $holdResults = $hold -split '(mbx|grp|skp|:|cld|UniH)'

                        switch ($holdResults[1]) {
                            'UniH' { $prefix = 'eDiscovery cases (holds) in the Security and Compliance Center' }
                            'cld' { $prefix = 'Exchange mailbox specific hold (in-place hold)' }
                            'mbx' { $prefix = 'Organization-wide retention policies applied to Exchange mailboxes, Exchange public folders, and 1xN chats in Microsoft Teams. Note 1xN chats are stored in the mailbox of the individual chat participants.' }
                            'grp' { $prefix = 'Organization-wide retention policies applied to Office 365 groups and channel messages in Microsoft Teams.' }
                            'skp' { $prefix = 'Indicates that the retention policy is configured to hold items and then delete them after the retention period expires.' }
                        }

                        switch ($holdResults[4]) {
                            1 { $retentionActionValueDescription = 'Indicates that the retention policy is configured to delete items. The policy does not retain items.' }
                            2 { $retentionActionValueDescription = 'Indicates that the retention policy is configured to hold items. The policy does not delete items after the retention period expires.' }
                            3 { $retentionActionValueDescription = 'Indicates that the retention policy is configured to hold items and then delete them after the retention period expires.' }
                        }

                        $inPlaceHoldsCustom = [PSCustomObject]@{
                            Prefix                     = $prefix
                            GUID                       = $holdResults[2]
                            RetentionAction            = $holdResults[4]
                            RetentionActionDescription = $retentionActionValueDescription
                        }
                        [PSCustomObject]$inPlaceHoldsCustom | Sort-Object | Export-Csv -Path (Join-Path -Path $OutputDirectory -ChildPath 'inPlaceHolds.csv') -Encoding utf8 -NoTypeInformation -Append
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
        Write-Output "Policy evaluation finished!"
    }
}
