# Get-CompliancePolicyCount
Calculate total number of O365 tenant wide compliance related policies

><b><span style="color:red">WARNING</span>: <span style="color:yellow">This data collection can contain sensitive information such as computer names, file names, and other PII / OII. Please vet files before sending to any support professionals for review!</span>

> <span style="color:red">NOTICE</span>: <span style="color:yellow"> When you run this script you acknowledge that you take full responsibility for the data collection and security of your private information!</span></b>

- EXAMPLE 1: Get-CompliancePolicyCount -UserPrincipalName admin@tenant.onmicrosoft.com -SaveResults

	Will connect to your tenant as your administrator, query all policy results and save them to disk for review.

- EXAMPLE 2: Get-CompliancePolicyCount -EnableDebugLogging

	Enable debugging logging. Transcript logs will be saved to c:\CompliancePolicyLogging\Transcript.log"

- EXAMPLE 3: Get-CompliancePolicyCount -SaveResults -Verbose

	Query compliance policy information and save the current scan to the default location of c:\CompliancePolicyLogging\PolicyResults.csv