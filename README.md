# Get-CompliancePolicyCount
Calculate total number of O365 tenant wide compliance related policies

> WARNING: This data collection can contain sensitive information such as computer names, file names, and other PII / OII. Please vet files before sending to any support professionals for review!

> <span style="color:red">NOTICE</span>: <span style="color:yellow"> When you run this script you acknowledge that you take full responsibility for the data collection and security of your private information!</span>

- EXAMPLES
  
> C:\PS> Get-CompliancePolicyCount -EnableDebugLogging

		Enable debugging logging. Transcript logs will be saved to c:\PolicyLogging\Transcript.log"

> C:\PS> Get-CompliancePolicyCount -UserPrincipalName admin@tenant.onmicrosoft.com

		Logs in to both Exchange online and the Security and Compliance workloads to pull compliance policy information

> C:\PS> Get-CompliancePolicyCount -SaveScanToDisk -Verbose

		Save the current scan to the default location of c:\PolicyLogging\PolicyResults.csv