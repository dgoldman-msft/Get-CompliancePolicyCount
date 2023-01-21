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
        Write-Output "$_"
        return
    }
}

function Remove-Sessions {
    <#
    .SYNOPSIS
        Close connections

    .DESCRIPTION
        Disconnect sessions to Exchange Online and Security and Compliance Center

    .EXAMPLE
        None

    .NOTES
        None
    #>

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param()

    try {
        Write-Output "Preforming session cleanup to: $($orgSettings.Name)"
        foreach ($session in Get-PSSession) {
            if ($session.ComputerName -like '*compliance*' -or $session.ComputerName -eq 'outlook.office365.com') {
                Write-Verbose "Removing session: $session.ComputerName"
                Remove-PSSession $session
            }
        }
    }
    catch {
        Write-Output "SESSION CLEANUP ERROR: $_"
     }
}

function Get-CompliancePolicyCount {
    <#
	.SYNOPSIS
		Calculate compliance policies

	.DESCRIPTION
		Calculate total number of O365 tenant wide compliance related policies

    .PARAMETER DisableProgressBar
        Disable the progress bar

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
		C:\PS> Get-CompliancePolicyCount -UserPrincipalName admin@tenant.onmicrosoft.com -SaveResults -DisableProgressBar

		Will connect to your tenant as your administrator, query all policy results and save them to disk for review and will not show the progress bar.

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
        $DisableProgressBar,

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
        $random = Get-Random
        $policyCounter = 0
        $maximumPolicyCount = 10000
        [System.Collections.ArrayList] $inPlaceHoldsList = @()
        [System.Collections.ArrayList] $dlpPolicyList = @()
        [System.Collections.ArrayList] $retentionPolicyList = @()
        [System.Collections.ArrayList] $standardDiscoveryCaseHoldsList = @()
        [System.Collections.ArrayList] $CaseHoldPolicyList = @()
        [System.Collections.ArrayList] $standardDiscoveryPolicyList = @()
        [System.Collections.ArrayList] $advancedDiscoveryPolicyList = @()
        $totalPolicies = @{'InPlaceHoldList' = $inPlaceHoldsList; 'dlpPolicyList' = $dlpPolicyList; 'retentionPolicyList' = $retentionPolicyList; `
                'standardDiscoveryPolicyList' = $standardDiscoveryPolicyList; 'standardDiscoveryCaseHoldsList' = $CaseHoldPolicyList; `
                'CaseHoldPolicyList' = $standardDiscoveryCaseHoldsList; 'advancedDiscoveryPolicyList' = $advancedDiscoveryPolicyList;
        }

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
            if (-NOT(Test-Path -Path $OutputDirectory -ErrorAction Stop)) {
                $null = New-Item -Path $OutputDirectory -ItemType Directory
                Write-Verbose "Created new directory: $($OutputDirectory)"
            }
            else {
                Write-Verbose "Directory: $($OutputDirectory) found!"
            }
        }
        catch {
            Write-Output "TEMP DIRECTORY ERROR: $_"
            return
        }
    }

    process {
        try {
            if ($UserPrincipalName -eq 'admin@tenant.onmicrosoft.com') { $UserPrincipalName = Read-Host -Prompt "Please enter an admin account" }

            Write-Verbose "Checking for the ExchangeOnlineManagement module"
            if (-NOT (Get-Module -Name ExchangeOnlineManagement -ListAvailable -ErrorAction Stop)) {
                Write-Verbose "Installing the ExchangeOnlineManagement module from the PowerShellGallery"
                if (Install-Module -Name ExchangeOnlineManagement -Repository PSGallery -Scope CurrentUser -Force -ErrorAction Stop) {
                    Import-Module -Name ExchangeOnlineManagement -Force
                    Write-Verbose "Importing ExchangeOnlineManagement complete"
                }
            }
            else {
                Write-Verbose "Importing the ExchangeOnlineManagement module"
                Import-Module -Name ExchangeOnlineManagement -Force
            }
        }
        catch {
            Write-Output "POWERSHELL MODULE ERROR: $_"
            return
        }

        try {
            Write-Output "Connecting to Exchange Online"
            Connect-ExchangeOnline -UserPrincipalName $UserPrincipalName -ShowBanner:$false -ShowProgress:$false -ErrorVariable failedConnection -ErrorAction Stop
            Write-Output "Connecting to the Security and Compliance Center"
            Connect-IPPSSession -UserPrincipalName $UserPrincipalName -ErrorVariable FailedConnection -ErrorAction Stop
        }
        catch {
            Write-Output "CONNECTION ERROR: $_"
            "CONNECTION FAILURE! Unable to connect to Exchange or the Security and Compliance endpoint. Please check the connection log for more information"
            Write-Output "Compliance policy evaluation completed with errors!"
            Remove-Sessions
            return
        }

        try {
            Write-Verbose "Querying Organization Configuration - In-place Hold Policies"
            if (($orgSettings = Get-OrganizationConfig -ErrorAction Stop | Select-Object Name, InPlaceHolds, GUID).InPlaceHolds.Count -ge 1) {
                foreach ($inPlaceHold in $orgSettings.InPlaceHolds) {
                    if (-NOT($parameters.ContainsKey('DisableProgressBar'))) {
                        $progressCounter = 1
                        Write-Progress -Activity "Querying Organization Configuration - In-place Hold Policies" -Status "Querying policy #: $progressCounter" -PercentComplete ($progressCounter / $($orgSettings.InPlaceHolds.count) * 100)
                        $progressCounter ++
                    }

                    $holdResults = (($inPlaceHold -split '(mbx|grp|skp|:|cld|UniH)') -match '\S')

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
                    $null = $inPlaceHoldsList.Add($inPlaceHoldsCustom)
                }
                $policyCounter += $inPlaceHoldsList.Count
            }
        }
        catch {
            Write-Output "ORGANIZATIONAL CONFIGURATION ERROR: $_"
        }

        try {
            # Retention policies in the Microsoft Purview compliance center
            Write-Verbose "Querying $($orgSettings.Name)'s retention polices"
            if (($retentionPolicies = Get-RetentionCompliancePolicy -ErrorAction Stop).Count -ge 1) {
                foreach ($retentionPolicy in $retentionPolicies) {
                    if (-NOT($parameters.ContainsKey('DisableProgressBar'))) {
                        Write-Progress -Activity "Querying $($orgSettings.Name)'s retention polices" -Status "Querying retention policy #: $progressCounter" -PercentComplete (1 / $retentionPolicies.count * 100)
                        $progressCounter ++
                    }
                    $null = $retentionPolicyList.Add($retentionPolicy)
                }
                Write-Verbose "Retention Policy Found: $($retentionPolicy)"
                $policyCounter += $retentionPolicyList.count
            }
        }
        catch {
            Write-Output "RETENTION POLICY ERROR: $_"
        }

        try {
            # Data loss prevention (DLP) policies in the Microsoft Purview compliance center
            Write-Verbose "Querying $($orgSettings.Name)'s DLP Policies"
            if (($dlpPolicies = Get-DlpCompliancePolicy -ErrorAction Stop).Count -ge 1) {
                foreach ($dlpPolicy in $dlpPolicies) {
                    if (-NOT($parameters.ContainsKey('DisableProgressBar'))) {
                        Write-Progress -Activity "Querying $($orgSettings.Name)'s DLP Policies" -Status "Querying DLP policy #: $progressCounter" -PercentComplete (1 / $dlpPolicies.count * 100)
                        $progressCounter ++
                    }
                    Write-Verbose "DLP Policy Found: $($dlpPolicy)"
                    $null = $dlpPolicyList.Add($dlpPolicy)
                }
                $policyCounter += $dlpPolicyList.count
            }
        }
        catch {
            Write-Output "DLP POLICY ERROR: $_"
        }

        try {
            # eDiscovery Standard cases in the Microsoft Purview compliance center
            Write-Verbose "Querying $($orgSettings.Name)'s standard eDiscovery cases"
            if ($standardDiscoveryCases = Get-ComplianceCase -ErrorAction Stop) {
                foreach ($standardCase in $standardDiscoveryCases) {
                    if (-NOT($parameters.ContainsKey('DisableProgressBar'))) {
                        Write-Progress -Activity "Querying $($orgSettings.Name)'s standard eDiscovery cases" -Status "Querying standard eDiscovery case #: $progressCounter" -PercentComplete (1 / $standardDiscoveryCases.count * 100)
                        $progressCounter ++
                    }
                    $null = $standardDiscoveryPolicyList.Add($standardCase)

                    Write-Verbose "Querying hold policies of $($orgSettings.Name)'s standard eDiscovery case with name: $($standardCase.name)"
                    if ($standardDiscoveryCaseHolds = Get-CaseHoldPolicy -Case $standardCase.Identity -ErrorAction Stop) {
                        foreach ($caseHoldPolicy in $standardDiscoveryCaseHolds) {
                            Write-Verbose "Found HoldPolicy in eDiscovery $($orgSettings.Name)'s standard eDiscovery cases with name $($caseHoldPolicy.name)"
                            $null = $standardDiscoveryCaseHoldsList.add($caseHoldPolicy)
                        }
                    }
                }
                $policyCounter += $standardDiscoveryPolicyList.count
                $policyCounter += $standardDiscoveryCaseHoldsList.count
            }
        }
        catch {
            Write-Output "STANDARD eDISCOVERY POLICY ERROR: $_"
        }

        try {
            # eDiscovery Advanced cases in the Microsoft Purview compliance center
            Write-Verbose "Querying $($orgSettings.Name)'s advanced eDiscovery Cases"
            if ($advancedEDiscoveryCases = Get-ComplianceCase -CaseType Advanced -ErrorAction Stop) {
                foreach ($advancedCase in $advancedEDiscoveryCases) {
                    if (-NOT($parameters.ContainsKey('DisableProgressBar'))) {
                        Write-Progress -Activity "Querying $($orgSettings.Name)'s advanced eDiscovery Cases" -Status "Querying advanced eDiscovery case #: $progressCounter" -PercentComplete (1 / $advancedEDiscoveryCases.count * 100)
                        $progressCounter ++
                    }
                    $null = $advancedDiscoveryPolicyList.Add($advancedCase)

                    Write-Verbose "Querying hold policies of $($orgSettings.Name)'s advanced eDiscovery case with name: $($advancedCase.name)"
                    if ($CaseHoldPolicies = Get-CaseHoldPolicy -Case $advancedCase.Identity -ErrorAction Stop) {
                        foreach ($caseHoldPolicy in $CaseHoldPolicies) {
                            Write-Verbose "Found HoldPolicy in eDiscovery $($orgSettings.Name)'s advanced eDiscovery cases with name $($caseHoldPolicy.name)"
                            $null = $CaseHoldPolicyList.add($caseHoldPolicy)
                        }
                    }
                }
                $policyCounter += $advancedDiscoveryPolicyList.count
                $policyCounter += $CaseHoldPolicyList.count
            }
        }
        catch {
            Write-Output "ADVANCED eDISCOVERY POLICY ERROR: $_"
        }

        try {
            if ($parameters.ContainsKey('SaveResults')) {
                Write-Output "Saving $($orgSettings.Name)'s compliance policy data to: $OutputDirectory"
                $totalPolicies.GetEnumerator() | ForEach-Object {
                    if (-NOT($_.Value.Count -eq 0)) {
                        LogToFile -DataToLog $_.Value -OutputDirectory $OutputDirectory -OutputFile "$($_.key)-$random.csv" -FileType 'csv' -ErrorAction Stop
                    }
                }

                # Save non ArrayList items
                $output = "The tenant has $($policyCounter) compliance policies and is under the maximum number of $maximumPolicyCount - OK (UNDER LIMIT)"
                LogToFile -DataToLog $output -OutputDirectory $OutputDirectory -Outputfile "TotalPolicyCount.txt" -FileType 'txt' -ErrorAction Stop
            }
        }
        catch {
            Write-Output "SAVING RESULTS ERROR: $_"
        }

        try {
            Write-Verbose "Archive and remove old files"
            Get-ChildItem -Path $OutputDirectory\*.txt, $OutputDirectory\*.csv -ErrorAction SilentlyContinue | Compress-Archive -DestinationPath "$OutputDirectory\OldFiles-Archive.$(get-date -f yyyy-MM-dd).zip" -Force -CompressionLevel Fastest -ErrorAction SilentlyContinue
            Remove-Item -Path $OutputDirectory\"*.*" -Exclude "*.zip", "*.ps1" -ErrorAction SilentlyContinue
        }
        catch {
            Write-Output "ARCHIVING ERROR: $_"
        }

        try {
            if ($parameters.ContainsKey('EnableDebugLogging')) {
                Write-Verbose "Stopping debug logging"
                Stop-Transcript
            }
        }
        catch {
            Write-Output "STOP DEBUG LOGGING ERROR: $_"
        }

        if ($policyCounter -ge $maximumPolicyCount) {
            $output = "The tenant has $policyCounter compliance policies! This exceeds the $maximumPolicyCount policies limit - ERROR! (OVER LIMIT)"
        }
        else {
            Write-Output "InPlace policies found: $($inPlaceHoldsList.count)"
            Write-Output "DLP policies found: $($dlpPolicyList.count)"
            Write-Output "Retention policies found: $($retentionPolicyList.count)"
            Write-Output "Standard eDiscovery cases found: $($standardDiscoveryPolicyList.count)"
            Write-Output "Standard Case holds found found: $($standardDiscoveryCaseHoldsList.count)"
            Write-Output "Advanced eDiscovery cases found: $($advancedDiscoveryPolicyList.count)"
            Write-Output "Advanced Case holds found found: $($CaseHoldPolicyList.count)"
            Write-Output "The tenant has $($policyCounter) compliance policies and is under the maximum number of $maximumPolicyCount - OK (UNDER LIMIT)"
        }
    }

    end {
        Write-Output "Completed!"
    }
}

