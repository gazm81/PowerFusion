<#
_____                                     ______                 _                 
|  __ \                                   |  ____|               (_)                
| |__) |   ___   __      __   ___   _ __  | |__     _   _   ___   _    ___    _ __  
|  ___/   / _ \  \ \ /\ / /  / _ \ | '__| |  __|   | | | | / __| | |  / _ \  | '_ \ 
| |      | (_) |  \ V  V /  |  __/ | |    | |      | |_| | \__ \ | | | (_) | | | | |
|_|       \___/    \_/\_/    \___| |_|    |_|       \__,_| |___/ |_|  \___/  |_| |_|
#>

# --- Clean up vRAConnection variable on module remove
$ExecutionContext.SessionState.Module.OnRemove = {

    Remove-Variable -Name FusionConnection -Force -ErrorAction SilentlyContinue

}
<#
    - Function: Connect-FusionServer
#>

function Connect-FusionServer {
<#
    .SYNOPSIS
    Connect to a Fusion Server

    .DESCRIPTION
    Connect to a Fusion Server and generate a connection object with Servername, Token etc

    .PARAMETER Server
    Fusion Server to connect to

    .PARAMETER Port
    Fusion Server Port to connect to

    .PARAMETER Username
    Username to connect with

    .PARAMETER Password
    Password to connect with

    .PARAMETER Credential
    Credential object to connect with

    .INPUTS
    System.String
    System.SecureString
    Management.Automation.PSCredential
    Switch

    .OUTPUTS
    System.Management.Automation.PSObject.

    .EXAMPLE
    Connect-FusionServer -Server 127.0.0.1 -port 8697 -Credential (Get-Credential)

    .EXAMPLE
    $SecurePassword = ConvertTo-SecureString “P@ssword” -AsPlainText -Force
    Connect-vRAServer -Server 127.0.0.1 -port 8697 -Username admin -Password $SecurePassword
#>
[CmdletBinding(DefaultParametersetName="Username")][OutputType('System.Management.Automation.PSObject')]

    Param (

        [parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [String]$Server = "127.0.0.1",

        [parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [String]$Port = "8697",

        [parameter(Mandatory=$true,ParameterSetName="Username")]
        [ValidateNotNullOrEmpty()]
        [String]$Username,

        [parameter(Mandatory=$true,ParameterSetName="Username")]
        [ValidateNotNullOrEmpty()]
        [SecureString]$Password,

        [Parameter(Mandatory=$true,ParameterSetName="Credential")]
        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]$Credential
    )

    # --- Convert Secure Credentials to a format for sending in the JSON payload
    if ($PSBoundParameters.ContainsKey("Credential")){

        $Username = $Credential.UserName
        $JSONPassword = $Credential.GetNetworkCredential().Password
    }

    if ($PSBoundParameters.ContainsKey("Password")){

        $JSONPassword = (New-Object System.Management.Automation.PSCredential("username", $Password)).GetNetworkCredential().Password
    }

    try {

        # --- Create a username:password pair
        $credPair = "$($Username):$($JSONPassword)"

        # --- Encode the pair to Base64 string
        $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))

        # --- Create Output Object
        $Global:FusionConnection = [PSCustomObject] @{

            Server = "http://$($Server):$($Port)"
            Token = $encodedCredentials
            Port = $Port
            Username = $Username
            APIVersion = "1.0"
        }

    }
    catch [Exception]{

        throw

    }

    Write-Output $FusionConnection

}

<#
    - Function: Disconnect-FusionServer
#>

function Disconnect-FusionServer {
<#
    .SYNOPSIS
    Disconnect from a Fusion server

    .DESCRIPTION
    Disconnect from a Fusion server by removing the authorization token and the global FusionConnection variable from PowerShell

    .EXAMPLE
    Disconnect-FusionServer

    .EXAMPLE
    Disconnect-FusionServer -Confirm:$false
#>
[CmdletBinding(SupportsShouldProcess,ConfirmImpact="High")]

    Param ()

    # --- Test for existing connection to vRA
    if (-not $Global:FusionConnection){

        throw "Fusion Connection variable does not exist. Please run Connect-FusionServer first to create it"
    }

    if ($PSCmdlet.ShouldProcess($Global:FusionConnection.Server)){
        Write-Verbose -Message "Removing vRAConnection global variable"
        Remove-Variable -Name vRAConnection -Scope Global -Force -ErrorAction SilentlyContinue
    }

}

<#
    - Function: Invoke-FusionRestMethod
#>

function Invoke-FusionRestMethod {
<#
    .SYNOPSIS
    Wrapper for Invoke-RestMethod/Invoke-WebRequest with Fusion specifics

    .DESCRIPTION
    Wrapper for Invoke-RestMethod/Invoke-WebRequest with Fusion specifics

    .PARAMETER Method
    REST Method:
    Supported Methods: GET, POST, PUT,DELETE

    .PARAMETER URI
    API URI, e.g. /identity/api/tenants

    .PARAMETER Headers
    Optionally supply custom headers

    .PARAMETER Body
    REST Body in JSON format

    .PARAMETER OutFile
    Save the results to a file

    .PARAMETER WebRequest
    Use Invoke-WebRequest rather than the default Invoke-RestMethod

    .INPUTS
    System.String
    Switch

    .OUTPUTS
    System.Management.Automation.PSObject

    .EXAMPLE
    Invoke-FusionRestMethod -Method GET -URI '/identity/api/tenants'

    .EXAMPLE
    $JSON = @"
        {
          "name" : "Tenant02",
          "description" : "This is Tenant02",
          "urlName" : "Tenant02",
          "contactEmail" : "test.user@tenant02.local",
          "id" : "Tenant02",
          "defaultTenant" : false,
          "password" : ""
        }
    "@

    Invoke-FusionRestMethod -Method PUT -URI '/identity/api/tenants/Tenant02' -Body $JSON -WebRequest
#>
[CmdletBinding(DefaultParameterSetName="Standard")][OutputType('System.Management.Automation.PSObject')]

    Param (

        [Parameter(Mandatory=$true, ParameterSetName="Standard")]
        [Parameter(Mandatory=$true, ParameterSetName="Body")]
        [Parameter(Mandatory=$true, ParameterSetName="OutFile")]
        [ValidateSet("GET","POST","PUT","DELETE")]
        [String]$Method,

        [Parameter(Mandatory=$true, ParameterSetName="Standard")]
        [Parameter(Mandatory=$true, ParameterSetName="Body")]
        [Parameter(Mandatory=$true, ParameterSetName="OutFile")]
        [ValidateNotNullOrEmpty()]
        [String]$URI,

        [Parameter(Mandatory=$false, ParameterSetName="Standard")]
        [Parameter(Mandatory=$false, ParameterSetName="Body")]
        [Parameter(Mandatory=$false, ParameterSetName="OutFile")]
        [ValidateNotNullOrEmpty()]
        [System.Collections.IDictionary]$Headers,

        [Parameter(Mandatory=$false, ParameterSetName="Body")]
        [ValidateNotNullOrEmpty()]
        [String]$Body,

        [Parameter(Mandatory=$false, ParameterSetName="OutFile")]
        [ValidateNotNullOrEmpty()]
        [String]$OutFile,

        [Parameter(Mandatory=$false, ParameterSetName="Standard")]
        [Parameter(Mandatory=$false, ParameterSetName="Body")]
        [Parameter(Mandatory=$false, ParameterSetName="OutFile")]
        [Switch]$WebRequest
    )

    # --- Test for existing connection to vRA
    if (-not $Global:FusionConnection){

        throw "Fusion Connection variable does not exist. Please run Connect-FusionServer first to create it"
    }

    # --- Create Invoke-RestMethod Parameters
    $FullURI = "$($Global:FusionConnection.Server)$($URI)"

    # --- Add default headers if not passed
    if (!$PSBoundParameters.ContainsKey("Headers")){

        $Headers = @{

            "Accept"="application/json";
            "Content-Type" = "application/json";
            "Authorization" = "Basic $($Global:FusionConnection.Token)";
        }
    }

    # --- Set up default parmaeters
    $Params = @{

        Method = $Method
        Headers = $Headers
        Uri = $FullURI
    }

    if ($PSBoundParameters.ContainsKey("Body")) {

        $Params.Add("Body", $Body)

        # --- Log the payload being sent to the server
        Write-Debug -Message $Body

    } elseif ($PSBoundParameters.ContainsKey("OutFile")) {

        $Params.Add("OutFile", $OutFile)

    }

    try {

        # --- Use either Invoke-WebRequest or Invoke-RestMethod
        if ($PSBoundParameters.ContainsKey("WebRequest")) {

            Invoke-WebRequest @Params
        }
        else {

            Invoke-RestMethod @Params
        }
    }
    catch {

        throw $_
    }
    finally {

        if (!$IsCoreCLR) {

            <#
                Workaround for bug in Invoke-RestMethod. Thanks to the PowerNSX guys for pointing this one out
                https://bitbucket.org/nbradford/powernsx/src
            #>
            $ServicePoint = [System.Net.ServicePointManager]::FindServicePoint($FullURI)
            $ServicePoint.CloseConnectionGroup("") | Out-Null
        }
    }
}

<#
    - Function: Get-FusionVm
#>

function Get-FusionVm {
    <#
        .SYNOPSIS
        Get a VMware Fusion Virtual Machine
        
        .DESCRIPTION
        Returns a vm or vm's Provisioned to VMware Fusion via the Rest API.
    
        .PARAMETER Id
        The id of the resource
        
        .INPUTS
        System.String
        System.Int
        Switch
    
        .OUTPUTS
        System.Management.Automation.PSObject.
    
        .EXAMPLE
        Get-FusionVm
    
        .EXAMPLE
        Get-FusionVm -Id "6195fd70"
    
    #>
    [CmdletBinding(DefaultParameterSetName="Standard")][OutputType('System.Management.Automation.PSObject')]
    
        Param (
    
            [Parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName="ById")]
            [ValidateNotNullOrEmpty()]
            [String[]]$Id
        )
    
        Begin {
    
            # --- Test for Fusion API version
    
        }
    
        Process {
    
            try {
    
                switch ($PsCmdlet.ParameterSetName) {
    
                    # --- Get Resource by id
                    'ById' {
                    
                        foreach ($ResourceId in $Id) { 
                    
                            $URI = "/api/vms/$($ResourceId)"
    
                            $EscapedURI = [uri]::EscapeUriString($URI)
    
                            $Response = Invoke-FusionRMethod -Method GET -URI $EscapedURI -Verbose:$VerbosePreference
    
                            if ($Response.content.Count -ne 0) {
                                intNewFusionObjectVm $Response.content
                            }
                            else {
                                Write-Verbose -Message "Could not find resource item with id: $($ResourceId)"
                            }
    
                        }
    
                        break
    
                    }        

                    # --- No parameters passed so return all resources
                    'Standard' {
    
                        # Fusion REST query is limited to only 100 items per page when extended data is requested. So the script must parse all pages returned
                        $nbPage = 1
                        $TotalPages = 99999 #Total pages is known after the 1st vRA REST query
                        
                        For ($nbPage=1; $nbPage -le $TotalPages; $nbPage++) {
                            # --- Set the default URI with no filtering to return all resource types
                            $URI = "/catalog-service/api/consumer/resourceViews/?withExtendedData=$($WithExtendedData)&withOperations=$($WithOperations)&managedOnly=$($ManagedOnly)&`$orderby=name asc&limit=$($Limit)&page=$($nbPage)"
    
                            # --- If type is passed set the filter
                            if ($PSBoundParameters.ContainsKey("Type")){
    
                                switch ($Type) {
    
                                    'Deployment' {
    
                                        $Filter = "resourceType/id eq 'composition.resource.type.deployment'"
                                        $URI = "$($URI)&`$filter=$($filter)"
    
                                        break
    
                                    }
    
                                    'Machine' {
    
                                        $Filter = "resourceType/id eq 'Infrastructure.Machine' or `
                                        resourceType/id eq 'Infrastructure.Virtual' or `
                                        resourceType/id eq 'Infrastructure.Cloud' or `
                                        resourceType/id eq 'Infrastructure.Physical'"
    
                                        $URI = "$($URI)&`$filter=$($filter)"
    
                                        break
    
                                    }
    
                                }
    
                                Write-Verbose -Message "Type $($Type) selected"
    
                            }
    
                            $EscapedURI = [uri]::EscapeUriString($URI)
    
                            try {
                                $Response = Invoke-vRARestMethod -Method GET -URI $EscapedURI -Verbose:$VerbosePreference
                                
                                foreach ($Resource in $Response.content) {
                                   intNewvRAObjectResource $Resource
                                }
    
                                $TotalPages = $Response.metadata.totalPages
                                Write-Verbose -Message "Total: $($Response.metadata.totalElements) | Page: $($nbPage) of $($TotalPages) | Size: $($Response.metadata.size)"
                            }
                            catch {
                                throw "An error occurred when getting vRA Resources! $($_.Exception.Message)"
                            }
                        }
                        
                        break
    
                    }
    
                }
    
            }
            catch [Exception]{
    
                throw
    
            }
    
        }
    
        End {
    
        }
    
    }
    
    Function intNewFusionObjectVm {
        Param (
            [Parameter(Mandatory=$true)]
            [ValidateNotNullOrEmpty()]
            $Data
        )
    
        [PSCustomObject]@{
            Id = $Data.Id
            Memory = $Data.Memory
        }
    }
    
    