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
        $TranscriptFile = "Transcript.log",

        [string]
        $UserPrincipalName = 'admin@tenant.onmicrosoft.com'
    )

    begin {
        Write-Output "Starting policy evaluation"
        $parameters = $PSBoundParameters
        $random = Get-Random
        $policyCounter = 0
        $maximumPolicyCount = 10000
        $savedErrorActionPreference = $ErrorActionPreference
        [System.Collections.ArrayList] $inPlaceHoldsList = @()
        [System.Collections.ArrayList] $retentionPolicyList = @()
        [System.Collections.ArrayList] $standardDiscoveryPolicyList = @()
        [System.Collections.ArrayList] $advancedDiscoveryPolicyList = @()
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
    }

    process {
        try {
            Write-Output "Connecting to Exchange Online"
            Connect-ExchangeOnline -UserPrincipalName $UserPrincipalName -ShowBanner:$false -ShowProgress:$false -ErrorVariable failedConnection
            Write-Output "Connecting to the Security and Compliance Center"
            Connect-IPPSSession -UserPrincipalName $UserPrincipalName -ErrorVariable FailedConnection
        }
        catch {
            Write-Output "ERROR: $_"
            return
        }

        try {
            Write-Verbose "Querying Organization Configuration - In-place Hold Policies"
            $orgSettings = Get-OrganizationConfig | Select-Object Name, InPlaceHolds, GUID
            foreach ($inPlaceHold in $orgSettings.InPlaceHolds) {
                $policyCounter ++
                $null = $inPlaceHoldsList.Add($inPlaceHold)
            }

            Write-Verbose "Querying $($orgSettings.Name)'s retention polices"
            # Retention policies in the Microsoft Purview compliance center
            $retentionPolicies = Get-RetentionCompliancePolicy
            foreach ($retentionPolicy in $retentionPolicies) {
                $policyCounter ++
                $null = $retentionPolicyList.Add($retentionPolicy)
            }

            Write-Verbose "Querying $($orgSettings.Name)'s standard eDiscovery cases"
            # eDiscovery Standard cases in the Microsoft Purview compliance center
            if ($standardDiscoveryCases = Get-ComplianceCase) {
                foreach ($standardCase in $standardDiscoveryCases) {
                    $policyCounter ++
                    $null = $standardDiscoveryPolicyList.Add($standardCase)
                    #Get-CaseHoldPolicy -Case $standardCase.Name
                    if (Get-ComplianceCaseMember -Case $standardCase.Name) {
                        $policyCounter ++
                    }
                }
            }
            else {
                $null = $standardDiscoveryPolicyList.Add("No standard eDiscovery cases found")
            }

            Write-Verbose "Querying $($orgSettings.Name)'s advanced eDiscovery Cases"
            # eDiscovery Advanced cases in the Microsoft Purview compliance center
            if ($advancedEDiscoveryCases = Get-ComplianceCase -CaseType Advanced) {
                foreach ($advancedCase in $advancedEDiscoveryCases) {
                    $policyCounter ++
                    # Case hold policies in the Microsoft Purview compliance center
                    #Get-CaseHoldPolicy -Case $advancedCase.Name
                    $null = $advancedDiscoveryPolicyList.Add($advancedCase)
                    if ($caseMember = Get-ComplianceCaseMember -Case $advancedCase.Name) {
                        $policyCounter ++

                        $caseMember = [PSCustomObject]@{
                            Alias                     = $caseMember.Alias
                            ArchiveGuid               = $caseMember.ArchiveGuid
                            ExternalDirectoryObjectId = $caseMember.ExternalDirectoryObjectId
                            DisplayName               = $caseMember.DisplayName
                            Guid                      = $caseMember.Guid
                            RecipientType             = $caseMember.RecipientType
                            WhenChanged               = $caseMember.WhenChanged
                        }
                        $null = $advancedDiscoveryPolicyMemberList.Add($caseMember)
                    }
                    else {
                        $null = $advancedDiscoveryPolicyMemberList.Add("No advanced eDiscovery case members found")
                    }
                }
            }
            else {
                $null = $advancedEDiscoveryCases.Add("No advanced eDiscovery cases found")
            }

            Write-Verbose "Querying $($orgSettings.Name)'s retention label policies"
            # (DLP) policies in the Microsoft Purview compliance portal.
            if ($retentionLabels = Get-DlpCompliancePolicy) { Write-Verbose "Retention labels found: $($retentionLabels.count)" }
            else { $retentionLabels = "No retention labels found" }

            if ($policyCounter -ge $maximumPolicyCount) {
                $output = "WARNING: The $($orgSettings.Name) tenant has $policyCounter compliance policies.. This exceeds the $maximumPolicyCount policies limit"
                Write-Output $output
            }
            else {
                $output = "The $($orgSettings.Name) tenant has $policyCounter compliance policies and is under the maximum number of $maximumPolicyCount"
                Write-Output $output
            }

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

            # Save policy count
            try {
                $policyCountLogFile = $env:COMPUTERNAME + "-$random-PolicyCount.txt"
                $output | Out-File -FilePath (Join-Path -Path $OutputDirectory -ChildPath $policyCountLogFile) -Encoding utf8
                Write-Output "Saving policy count data to: $OutputDirectory\$policyCountLogFile"
            }
            catch {
                Write-Output "ERROR: $_"
                return
            }

            if ($parameters.ContainsKey('SaveResults')) {
                try {
                    Write-Output "Saving $($orgSettings.Name)'s compliance policy data to: $OutputDirectory"
                    [PSCustomObject]$retentionPolicyList | Sort-Object | Export-Csv -Path (Join-Path -Path $OutputDirectory -ChildPath "RetentionPolicyList-$random-.csv") -Encoding utf8 -NoTypeInformation
                    [PSCustomObject]$standardDiscoveryPolicies | Sort-Object | Export-Csv -Path (Join-Path -Path $OutputDirectory -ChildPath "StandardDiscoveryPolicies-$random-.csv") -Encoding utf8 -NoTypeInformation
                    [PSCustomObject]$advancedDiscoveryPolicies | Sort-Object | Export-Csv -Path (Join-Path -Path $OutputDirectory -ChildPath "AdvancedDiscoveryPolicies-$random-.csv") -Encoding utf8 -NoTypeInformation
                    [PSCustomObject]$advancedEDiscoveryCaseMembers | Sort-Object | Export-Csv -Path (Join-Path -Path $OutputDirectory -ChildPath "advancedEDiscoveryCaseMembers-$random-.csv") -Encoding utf8 -NoTypeInformation

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
                        [PSCustomObject]$inPlaceHoldsCustom | Sort-Object | Export-Csv -Path (Join-Path -Path $OutputDirectory -ChildPath "inPlaceHolds-$random-.csv") -Encoding utf8 -NoTypeInformation -Append
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
        if ($failedConnection) { "CONNECTION FAILURE! Unable to connect to Exchange or the Security and Compliance endpoint. Please check the logs for more information" }
        elseif ($orgSettings.Name) { Write-Output "Compliance policy evaluation of $($orgSettings.Name) completed!" }
        else { Write-Output "Compliance policy evaluation completed!" }
    }
}
