<#
 _____                                     ______                 _                 
|  __ \                                   |  ____|               (_)                
| |__) |   ___   __      __   ___   _ __  | |__     _   _   ___   _    ___    _ __  
|  ___/   / _ \  \ \ /\ / /  / _ \ | '__| |  __|   | | | | / __| | |  / _ \  | '_ \ 
| |      | (_) |  \ V  V /  |  __/ | |    | |      | |_| | \__ \ | | | (_) | | | | |
|_|       \___/    \_/\_/    \___| |_|    |_|       \__,_| |___/ |_|  \___/  |_| |_|
#>

#region Init and Common

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

            "Accept"        = "application/vnd.vmware.vmw.rest-v1+json";
            "Content-Type"  = "application/vnd.vmware.vmw.rest-v1+json";
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

#endregion

#region - Host Networks Management

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

function Set-FusionNetworkPortForward {
    param (
        $OptionalParameters
    )
}

function Remove-FusionNetworkPortForward {
    <#
        .SYNOPSIS
        Deletes a fusion network port forward
        
        .DESCRIPTION
        Deletes a fusion network port forward
    
        .PARAMETER Vmnet
        NAT type of the virtual network

        .PARAMETER Protocol
        Protocol type - TCP or UDP

        .PARAMETER Port
        Port number at the host level

        .INPUTS
        System.String.
    
        .OUTPUTS
        System.Management.Automation.PSObject
    
        .EXAMPLE
        Delete-FusionNetworkPortForward -Vmnet "" -Protocol "" -Port ""
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = "Low", DefaultParameterSetName = "ById")][OutputType('System.Management.Automation.PSObject')]
    
    Param (
    
        [Parameter(Mandatory = $true, ParameterSetName = "ById")]
        [ValidateNotNullOrEmpty()]
        [String]$Vmnet,

        [Parameter(Mandatory = $true, ParameterSetName = "ById")]
        [ValidateNotNullOrEmpty()]
        [String]$Protocol,

        [Parameter(Mandatory = $true, ParameterSetName = "ById")]
        [ValidateNotNullOrEmpty()]
        [String]$Port
    )
    
    begin {
    }
        
    process {
    }
    end {
    
        # --- Convert PSCustomObject to a string                 
    
        if ($PSCmdlet.ShouldProcess($Name)) {
    
            $URI = "/api/vms/$($Id)/nic/$($Index)"
    
            # --- Run Fusion REST Request
            $Response = Invoke-FusionRestMethod -Method DELETE -URI $URI -Verbose:$VerbosePreference
    
            # --- Output the Successful Result
            If ($Response.id) {$Response} else {
                $Response
            }
        }   
    }
}

#endregion

#region - VM Management

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

function Set-FusionVm {
    <#
            .SYNOPSIS
            Set the config of the fusion VM
            
            .DESCRIPTION
            Set the config of the fusion VM
        
            .PARAMETER Id
            A list of the vm ids
        
            .PARAMETER processors
            the desired number of cpus

            .PARAMETER memory
            desired amount of memory mb
        
            .INPUTS
            System.String.
        
            .OUTPUTS
            System.Management.Automation.PSObject
        
            .EXAMPLE
            Set-FusionVm -id "12345" -Cpus 2 -MemoryMb 4096
        #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = "Low", DefaultParameterSetName = "ById")][OutputType('System.Management.Automation.PSObject')]
        
    Param (
        
        [Parameter(Mandatory = $true, ParameterSetName = "ById")]
        [ValidateNotNullOrEmpty()]
        [String[]]$Id,
        
        [Parameter(Mandatory = $true, ParameterSetName = "ById")]
        [ValidateNotNullOrEmpty()]
        [String]$processors,

        [Parameter(Mandatory = $true, ParameterSetName = "ById")]
        [ValidateNotNullOrEmpty()]
        [String]$memory
    )
        
    begin {
        $Object = [PSCustomObject] @{
            processors = $processors
            memory     = $memory
        }
    }
            
    process {
    }

    end {
        
        # --- Convert PSCustomObject to a string
        $Body = $Object | ConvertTo-Json                    
        
        if ($PSCmdlet.ShouldProcess($Name)) {
        
            $URI = "/api/vms/$Id"
        
            # --- Run Fusion REST Request
            Invoke-FusionRestMethod -Method PUT -URI $URI -Body $Body -Verbose:$VerbosePreference | Out-Null
        
            # --- Output the Successful Result
            Get-FusionVm -id $Id -Verbose:$VerbosePreference
        }   
    }
}

function Clone-FusionVm {
    <#
        .SYNOPSIS
        Creates a new fusion vm via cloning existing fusion vm
        
        .DESCRIPTION
        Creates a new fusion vm via cloning existing fusion vm
    
        .PARAMETER ParentId
        ID of the VM to be cloned
    
        .PARAMETER Name
        Name of the new VM
    
        .INPUTS
        System.String.
    
        .OUTPUTS
        System.Management.Automation.PSObject
    
        .EXAMPLE
        Clone-FusionVm -ParentiId "12345" -Name "NewMachine01"
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = "Low", DefaultParameterSetName = "ById")][OutputType('System.Management.Automation.PSObject')]
    
    Param (
    
        [Parameter(Mandatory = $true, ParameterSetName = "ById")]
        [ValidateNotNullOrEmpty()]
        [String]$ParentId,
    
        [Parameter(Mandatory = $true, ParameterSetName = "ById")]
        [ValidateNotNullOrEmpty()]
        [String]$Name
    )
    
    begin {
        $Object = [PSCustomObject] @{
            name     = $Name
            parentId = $ParentId
        }
    }
        
    process {
    }
    end {
    
        # --- Convert PSCustomObject to a string
        $Body = $Object | ConvertTo-Json                   
    
        if ($PSCmdlet.ShouldProcess($Name)) {
    
            $URI = "/api/vms"
    
            # --- Run Fusion REST Request
            $Response = Invoke-FusionRestMethod -Method POST -URI $URI -Body $Body -Verbose:$VerbosePreference
    
            # --- Output the Successful Result
            If ($Response.id) {$Response} else {
                $Response
            }
        }   
    }
}

function Delete-FusionVm {
    <#
        .SYNOPSIS
        Deletes a fusion vm
        
        .DESCRIPTION
        Deletes a fusion vm
    
        .PARAMETER Id
        ID of the VM to be cloned
    
        .INPUTS
        System.String.
    
        .OUTPUTS
        System.Management.Automation.PSObject
    
        .EXAMPLE
        Delete-FusionVm -Id "12345"
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = "Low", DefaultParameterSetName = "ById")][OutputType('System.Management.Automation.PSObject')]
    
    Param (
    
        [Parameter(Mandatory = $true, ParameterSetName = "ById")]
        [ValidateNotNullOrEmpty()]
        [String]$Id
    )
    
    begin {
    }
        
    process {
    }
    end {
    
        # --- Convert PSCustomObject to a string                 
    
        if ($PSCmdlet.ShouldProcess($Name)) {
    
            $URI = "/api/vms/$($Id)"
    
            # --- Run Fusion REST Request
            $Response = Invoke-FusionRestMethod -Method DELETE -URI $URI -Verbose:$VerbosePreference
    
            # --- Output the Successful Result
            If ($Response.id) {$Response} else {
                $Response
            }
        }   
    }
}

#endregion

#region - VM Network Adapters Management

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
                                    index = $R.index
                                    type  = $R.type
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
                                    ip = $R.ip
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

function Set-FusionVmNetworkAdapter {
    param (
        $OptionalParameters
    )   
}

function Create-FusionVmNetworkAdapter {
    param (
        $OptionalParameters
    )   
}

function Delete-FusionVmNetworkAdapter {
    <#
        .SYNOPSIS
        Deletes a fusion vm network adapter by index
        
        .DESCRIPTION
        Deletes a fusion vm network adapter by index
    
        .PARAMETER Id
        ID of the target VM

        .PARAMETER Index
        Index Number of the target VM network adapter
    
        .INPUTS
        System.String.
    
        .OUTPUTS
        System.Management.Automation.PSObject
    
        .EXAMPLE
        Delete-FusionVmNetworkadapter -Id "12345" -Index "1"
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = "Low", DefaultParameterSetName = "ById")][OutputType('System.Management.Automation.PSObject')]
    
    Param (
    
        [Parameter(Mandatory = $true, ParameterSetName = "ById")]
        [ValidateNotNullOrEmpty()]
        [String]$Id,

        [Parameter(Mandatory = $true, ParameterSetName = "ById")]
        [ValidateNotNullOrEmpty()]
        [String]$Index
    )
    
    begin {
    }
        
    process {
    }
    end {
    
        # --- Convert PSCustomObject to a string                 
    
        if ($PSCmdlet.ShouldProcess($Name)) {
    
            $URI = "/api/vms/$($Id)/nic/$($Index)"
    
            # --- Run Fusion REST Request
            $Response = Invoke-FusionRestMethod -Method DELETE -URI $URI -Verbose:$VerbosePreference
    
            # --- Output the Successful Result
            If ($Response.id) {$Response} else {
                $Response
            }
        }   
    }
}

#endregion

#region - VM Power Management

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
                                    power_state = $R.power_state
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
function Set-FusionVmPower {
    <#
        .SYNOPSIS
        Set the power state on a fusion VM
        
        .DESCRIPTION
        Set the power state on a fusion VM
    
        .PARAMETER Id
        A list of the vm ids
    
        .PARAMETER PowerState
        the desired power state
    
        .INPUTS
        System.String.
    
        .OUTPUTS
        System.Management.Automation.PSObject
    
        .EXAMPLE
        Set-FusionVmPower -id "12345" -PowerState "on"
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = "Low", DefaultParameterSetName = "ById")][OutputType('System.Management.Automation.PSObject')]
    
    Param (
    
        [Parameter(Mandatory = $true, ParameterSetName = "ById")]
        [ValidateNotNullOrEmpty()]
        [String[]]$Id,
    
        [Parameter(Mandatory = $true, ParameterSetName = "ById")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("on", "off", "shutdown", "suspend", "pause", "unpause")]
        [String]$PowerState
    )
    
    begin {
    }
        
    process {
    }
    end {
    
        # --- Convert PSCustomObject to a string
        $Body = $PowerState                    
    
        if ($PSCmdlet.ShouldProcess($Name)) {
    
            $URI = "/api/vms/$Id/power"
    
            # --- Run Fusion REST Request
            Invoke-FusionRestMethod -Method PUT -URI $URI -Body $Body -Verbose:$VerbosePreference | Out-Null
    
            # --- Output the Successful Result
            Get-FusionVmPower -id $Id -Verbose:$VerbosePreference
        }   
    }
}

#endregion

#region - VM Shared Folders Management

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
                                    power_state = $R.power_state
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

function Set-FusionVmSharedFolders {
    param (
        $OptionalParameters
    )
    
}

function Mount-FusionVmSharedFolders {
    param (
        $OptionalParameters
    )
    
}

function Delete-FusionVmSharedFolders {
    <#
        .SYNOPSIS
        Deletes a fusion vm network adapter by index
        
        .DESCRIPTION
        Deletes a fusion vm network adapter by index
    
        .PARAMETER Id
        ID of the target VM

        .PARAMETER Index
        Index Number of the target VM network adapter
    
        .INPUTS
        System.String.
    
        .OUTPUTS
        System.Management.Automation.PSObject
    
        .EXAMPLE
        Delete-FusionVmNetworkadapter -Id "12345" -Index "1"
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = "Low", DefaultParameterSetName = "ById")][OutputType('System.Management.Automation.PSObject')]
    
    Param (
    
        [Parameter(Mandatory = $true, ParameterSetName = "ById")]
        [ValidateNotNullOrEmpty()]
        [String]$Id,

        [Parameter(Mandatory = $true, ParameterSetName = "ById")]
        [ValidateNotNullOrEmpty()]
        [String]$Index
    )
    
    begin {
    }
        
    process {
    }
    end {
    
        # --- Convert PSCustomObject to a string                 
    
        if ($PSCmdlet.ShouldProcess($Name)) {
    
            $URI = "/api/vms/$($Id)/nic/$($Index)"
    
            # --- Run Fusion REST Request
            $Response = Invoke-FusionRestMethod -Method DELETE -URI $URI -Verbose:$VerbosePreference
    
            # --- Output the Successful Result
            If ($Response.id) {$Response} else {
                $Response
            }
        }   
    }
}

#endregion