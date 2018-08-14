<#
_____                                     ______                 _                 
|  __ \                                   |  ____|               (_)                
| |__) |   ___   __      __   ___   _ __  | |__     _   _   ___   _    ___    _ __  
|  ___/   / _ \  \ \ /\ / /  / _ \ | '__| |  __|   | | | | / __| | |  / _ \  | '_ \ 
| |      | (_) |  \ V  V /  |  __/ | |    | |      | |_| | \__ \ | | | (_) | | | | |
|_|       \___/    \_/\_/    \___| |_|    |_|       \__,_| |___/ |_|  \___/  |_| |_|
#>

# --- Clean up FusionConnection variable on module remove
$ExecutionContext.SessionState.Module.OnRemove = {
    Remove-Variable -Name FusionConnection -Force -ErrorAction SilentlyContinue
}
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
    [CmdletBinding(DefaultParametersetName = "Username")][OutputType('System.Management.Automation.PSObject')]

    Param (

        [parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]$Server = "127.0.0.1",

        [parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]$Port = "8697",

        [parameter(Mandatory = $true, ParameterSetName = "Username")]
        [ValidateNotNullOrEmpty()]
        [String]$Username,

        [parameter(Mandatory = $true, ParameterSetName = "Username")]
        [ValidateNotNullOrEmpty()]
        [SecureString]$Password,

        [Parameter(Mandatory = $true, ParameterSetName = "Credential")]
        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]$Credential
    )

    # --- Convert Secure Credentials to a format for sending in the JSON payload
    if ($PSBoundParameters.ContainsKey("Credential")) {

        $Username = $Credential.UserName
        $JSONPassword = $Credential.GetNetworkCredential().Password
    }

    if ($PSBoundParameters.ContainsKey("Password")) {

        $JSONPassword = (New-Object System.Management.Automation.PSCredential("username", $Password)).GetNetworkCredential().Password
    }

    try {

        # --- Create a username:password pair
        $credPair = "$($Username):$($JSONPassword)"

        # --- Encode the pair to Base64 string
        $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))

        # --- Create Output Object
        $Global:FusionConnection = [PSCustomObject] @{

            Server     = "http://$($Server):$($Port)"
            Token      = $encodedCredentials
            Port       = $Port
            Username   = $Username
            APIVersion = "1.0"
        }

    }
    catch [Exception] {

        throw

    }

    Write-Output $FusionConnection

}
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
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = "High")]

    Param ()

    # --- Test for existing connection to vRA
    if (-not $Global:FusionConnection) {

        throw "Fusion Connection variable does not exist. Please run Connect-FusionServer first to create it"
    }

    if ($PSCmdlet.ShouldProcess($Global:FusionConnection.Server)) {
        Write-Verbose -Message "Removing vRAConnection global variable"
        Remove-Variable -Name FusionConnection -Scope Global -Force -ErrorAction SilentlyContinue
    }

}
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
    [CmdletBinding(DefaultParameterSetName = "Standard")][OutputType('System.Management.Automation.PSObject')]

    Param (

        [Parameter(Mandatory = $true, ParameterSetName = "Standard")]
        [Parameter(Mandatory = $true, ParameterSetName = "Body")]
        [Parameter(Mandatory = $true, ParameterSetName = "OutFile")]
        [ValidateSet("GET", "POST", "PUT", "DELETE")]
        [String]$Method,

        [Parameter(Mandatory = $true, ParameterSetName = "Standard")]
        [Parameter(Mandatory = $true, ParameterSetName = "Body")]
        [Parameter(Mandatory = $true, ParameterSetName = "OutFile")]
        [ValidateNotNullOrEmpty()]
        [String]$URI,

        [Parameter(Mandatory = $false, ParameterSetName = "Standard")]
        [Parameter(Mandatory = $false, ParameterSetName = "Body")]
        [Parameter(Mandatory = $false, ParameterSetName = "OutFile")]
        [ValidateNotNullOrEmpty()]
        [System.Collections.IDictionary]$Headers,

        [Parameter(Mandatory = $false, ParameterSetName = "Body")]
        [ValidateNotNullOrEmpty()]
        [String]$Body,

        [Parameter(Mandatory = $false, ParameterSetName = "OutFile")]
        [ValidateNotNullOrEmpty()]
        [String]$OutFile,

        [Parameter(Mandatory = $false, ParameterSetName = "Standard")]
        [Parameter(Mandatory = $false, ParameterSetName = "Body")]
        [Parameter(Mandatory = $false, ParameterSetName = "OutFile")]
        [Switch]$WebRequest
    )

    # --- Test for existing connection to vRA
    if (-not $Global:FusionConnection) {

        throw "Fusion Connection variable does not exist. Please run Connect-FusionServer first to create it"
    }

    # --- Create Invoke-RestMethod Parameters
    $FullURI = "$($Global:FusionConnection.Server)$($URI)"

    # --- Add default headers if not passed
    if (!$PSBoundParameters.ContainsKey("Headers")) {

        $Headers = @{

            "Accept"        = "application/json";
            "Content-Type"  = "application/json";
            "Authorization" = "Basic $($Global:FusionConnection.Token)";
        }
    }

    # --- Set up default parmaeters
    $Params = @{

        Method  = $Method
        Headers = $Headers
        Uri     = $FullURI
    }

    if ($PSBoundParameters.ContainsKey("Body")) {

        $Params.Add("Body", $Body)

        # --- Log the payload being sent to the server
        Write-Debug -Message $Body

    }
    elseif ($PSBoundParameters.ContainsKey("OutFile")) {

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
    
        .OUTPUTS
        System.Management.Automation.PSObject.
    
        .EXAMPLE
        Get-FusionVm
    
        .EXAMPLE
        Get-FusionVm -Id "6195fd70"
    
    #>
    [CmdletBinding(DefaultParameterSetName = "Standard")][OutputType('System.Management.Automation.PSObject')]
    
    Param (
    
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = "ById")]
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
    
                        $Response = Invoke-FusionRestMethod -Method GET -URI $EscapedURI -Verbose:$VerbosePreference
    
                        if ($Response) {
                            foreach ($R in $Response) {
                                [PSCustomObject]@{
                                    id     = $R.id
                                    #processors = $R.cpu.processors
                                    cpu    = @{processors = $R.cpu.processors}
                                    memory = $R.memory   
                                }
                            }
                        }
                        else {
                            Write-Verbose -Message "Could not find resource item with id: $($ResourceId)"
                        }
                    }    
                    break   
                }        

                # --- No parameters passed so return all resources
                'Standard' {
       
                    $EscapedURI = [uri]::EscapeUriString("/api/vms")

                    try {
                        $Response = Invoke-FusionRestMethod -Method GET -URI $EscapedURI -Verbose:$VerbosePreference
                            
                        if ($Response) {
                            foreach ($R in $Response) {
                                [PSCustomObject]@{
                                    id   = $R.id
                                    path = $R.path
                                }
                            }
                        }
                    }
                    catch {
                        throw "An error occurred when getting Fusion Resources! $($_.Exception.Message)"
                    }                        
                    break
                }
            }
        }
        catch [Exception] {
            throw
        }
    }   
    End {    
    }    
}
function Get-FusionNetwork {
    <#
        .SYNOPSIS
        Get a VMware Fusion Network
        
        .DESCRIPTION
        Returns a network or networks usable in VMware Fusion via the Rest API.
    
        .OUTPUTS
        System.Management.Automation.PSObject.
    
        .EXAMPLE
        Get-FusionNetwork
    
    #>
    [CmdletBinding(DefaultParameterSetName = "Standard")][OutputType('System.Management.Automation.PSObject')]
    
    Param (
    )
    
    Begin {
    
        # --- Test for Fusion API version
    
    }
    
    Process {
    
        try {
    
            switch ($PsCmdlet.ParameterSetName) {     

                # --- No parameters passed so return all resources
                'Standard' {
       
                    $EscapedURI = [uri]::EscapeUriString("/api/vmnet")

                    try {
                        $Response = Invoke-FusionRestMethod -Method GET -URI $EscapedURI -Verbose:$VerbosePreference
                            
                        if ($Response) {
                            foreach ($R in $Response.vmnets) {
                                [PSCustomObject]@{
                                    name   = $R.name
                                    type   = $R.type
                                    dhcp   = $R.dhcp
                                    subnet = $R.subnet
                                    mask   = $R.mask
                                }
                            }
                        }
                    }
                    catch {
                        throw "An error occurred when getting Fusion Resources! $($_.Exception.Message)"
                    }                        
                    break
                }
            }
        }
        catch [Exception] {
            throw
        }
    }   
    End {    
    }    
}
function Get-FusionNetworkPortForward {
    <#
        .SYNOPSIS
        Get a VMware Fusion Network Port Forward
        
        .DESCRIPTION
        Returns a network Port Forwarder/s per network in VMware Fusion via the Rest API.

        .PARAMETER Id
        The vmnet id of the network resource

        .INPUTS
        String
    
        .OUTPUTS
        System.Management.Automation.PSObject.
    
        .EXAMPLE
        Get-FusionNetworkPortForward -vmnet
    
    #>
    [CmdletBinding(DefaultParameterSetName = "Standard")][OutputType('System.Management.Automation.PSObject')]
    
    Param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = "Standard")]
        [ValidateNotNullOrEmpty()]
        [String[]]$id       
    )
    
    Begin {
    
        # --- Test for Fusion API version
    
    }
    
    Process {
    
        try {
    
            switch ($PsCmdlet.ParameterSetName) {     

                # --- No parameters passed so return all resources
                'Standard' {
       
                    $EscapedURI = [uri]::EscapeUriString("/api/vmnet/$($id)/portforward")

                    try {
                        $Response = Invoke-FusionRestMethod -Method GET -URI $EscapedURI -Verbose:$VerbosePreference
                            
                        if ($Response) {
                            foreach ($R in $Response) {
                                [PSCustomObject]@{
                                    num              = $R.num
                                    port_forwardings = $R.port_forwardings
                                }
                            }
                        }
                    }
                    catch {
                        throw "An error occurred when getting Fusion Resources! $($_.Exception.Message)"
                    }                        
                    break
                }
            }
        }
        catch [Exception] {
            throw
        }
    }   
    End {    
    }    
}
function Get-FusionVmNetworkAdapter {
    <#
        .SYNOPSIS
        Get a VMware Fusion VM Network Adapter
        
        .DESCRIPTION
        Returns a VM network adapter per VM in VMware Fusion via the Rest API.

        .PARAMETER Id
        The vmnet id of the vm

        .INPUTS
        String
    
        .OUTPUTS
        System.Management.Automation.PSObject.
    
        .EXAMPLE
        Get-FusionVmNetworkAdapter -id "AHA7A1"
    
    #>
    [CmdletBinding(DefaultParameterSetName = "Standard")][OutputType('System.Management.Automation.PSObject')]
    
    Param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = "Standard")]
        [ValidateNotNullOrEmpty()]
        [String[]]$id       
    )
    
    Begin {
    
        # --- Test for Fusion API version
    
    }
    
    Process {
    
        try {
    
            switch ($PsCmdlet.ParameterSetName) {     

                # --- No parameters passed so return all resources
                'Standard' {
       
                    $EscapedURI = [uri]::EscapeUriString("/api/vms/$($id)/nic")

                    try {
                        $Response = Invoke-FusionRestMethod -Method GET -URI $EscapedURI -Verbose:$VerbosePreference
                            
                        if ($Response) {
                            foreach ($R in $Response.nics) {
                                [PSCustomObject]@{
                                    index              = $R.index
                                    type = $R.type
                                    vmnet = $R.vmnet
                                }
                            }
                        }
                    }
                    catch {
                        throw "An error occurred when getting Fusion Resources! $($_.Exception.Message)"
                    }                        
                    break
                }
            }
        }
        catch [Exception] {
            throw
        }
    }   
    End {    
    }    
}
function Get-FusionVmNetworkIp {
    <#
        .SYNOPSIS
        Get a VMware Fusion VM Network IP
        
        .DESCRIPTION
        Returns a VM network IP per VM in VMware Fusion via the Rest API.

        .PARAMETER Id
        The vmnet id of the vm

        .INPUTS
        String
    
        .OUTPUTS
        System.Management.Automation.PSObject.
    
        .EXAMPLE
        Get-FusionVmNetworkIp -id "AHA7A1"
    
    #>
    [CmdletBinding(DefaultParameterSetName = "Standard")][OutputType('System.Management.Automation.PSObject')]
    
    Param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = "Standard")]
        [ValidateNotNullOrEmpty()]
        [String[]]$id       
    )
    
    Begin {
    
        # --- Test for Fusion API version
    
    }
    
    Process {
    
        try {
    
            switch ($PsCmdlet.ParameterSetName) {     

                # --- No parameters passed so return all resources
                'Standard' {
       
                    $EscapedURI = [uri]::EscapeUriString("/api/vms/$($id)/ip")

                    try {
                        $Response = Invoke-FusionRestMethod -Method GET -URI $EscapedURI -Verbose:$VerbosePreference
                            
                        if ($Response) {
                            foreach ($R in $Response) {
                                [PSCustomObject]@{
                                    ip              = $R.ip
                                }
                            }
                        }
                    }
                    catch {
                        throw "An error occurred when getting Fusion Resources! $($_.Exception.Message)"
                    }                        
                    break
                }
            }
        }
        catch [Exception] {
            throw
        }
    }   
    End {    
    }    
}
function Get-FusionVmPower {
    <#
        .SYNOPSIS
        Get a VMware Fusion VM Power State
        
        .DESCRIPTION
        Returns a VM Power State in VMware Fusion via the Rest API.

        .PARAMETER Id
        The vmnet id of the vm

        .INPUTS
        String
    
        .OUTPUTS
        System.Management.Automation.PSObject.
    
        .EXAMPLE
        Get-FusionVmPower -id "AHA7A1"
    
    #>
    [CmdletBinding(DefaultParameterSetName = "Standard")][OutputType('System.Management.Automation.PSObject')]
    
    Param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = "Standard")]
        [ValidateNotNullOrEmpty()]
        [String[]]$id       
    )
    
    Begin {
    
        # --- Test for Fusion API version
    
    }
    
    Process {
    
        try {
    
            switch ($PsCmdlet.ParameterSetName) {     

                # --- No parameters passed so return all resources
                'Standard' {
       
                    $EscapedURI = [uri]::EscapeUriString("/api/vms/$($id)/power")

                    try {
                        $Response = Invoke-FusionRestMethod -Method GET -URI $EscapedURI -Verbose:$VerbosePreference
                            
                        if ($Response) {
                            foreach ($R in $Response) {
                                [PSCustomObject]@{
                                    power_state              = $R.power_state
                                }
                            }
                        }
                    }
                    catch {
                        throw "An error occurred when getting Fusion Resources! $($_.Exception.Message)"
                    }                        
                    break
                }
            }
        }
        catch [Exception] {
            throw
        }
    }   
    End {    
    }    
}
function Get-FusionVmSharedFolders {
    <#
        .SYNOPSIS
        Get a VMware Fusion VM Shared Folders
        
        .DESCRIPTION
        Returns a VM's shared folders in VMware Fusion via the Rest API.

        .PARAMETER Id
        The vmnet id of the vm

        .INPUTS
        String
    
        .OUTPUTS
        System.Management.Automation.PSObject.
    
        .EXAMPLE
        Get-FusionVmShareFolder -id "AHA7A1"
    
    #>
    [CmdletBinding(DefaultParameterSetName = "Standard")][OutputType('System.Management.Automation.PSObject')]
    
    Param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = "Standard")]
        [ValidateNotNullOrEmpty()]
        [String[]]$id       
    )
    
    Begin {
    
        # --- Test for Fusion API version
    
    }
    
    Process {
    
        try {
    
            switch ($PsCmdlet.ParameterSetName) {     

                # --- No parameters passed so return all resources
                'Standard' {
       
                    $EscapedURI = [uri]::EscapeUriString("/api/vms/$($id)/sharedfolders")

                    try {
                        $Response = Invoke-FusionRestMethod -Method GET -URI $EscapedURI -Verbose:$VerbosePreference
                            
                        if ($Response) {
                            foreach ($R in $Response) {
                                [PSCustomObject]@{
                                    power_state              = $R.power_state
                                }
                            }
                        }
                    }
                    catch {
                        throw "An error occurred when getting Fusion Resources! $($_.Exception.Message)"
                    }                        
                    break
                }
            }
        }
        catch [Exception] {
            throw
        }
    }   
    End {    
    }    
}