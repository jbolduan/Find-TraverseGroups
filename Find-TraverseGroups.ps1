[CmdletBinding()]
param(
	[Parameter(Mandatory=$true)][string]$Path="C:\Users\jbolduan\Desktop\testtrav"
)

# Import active directory module
Import-Module ActiveDirectory

$TraveerseGroups = @()

# Build tests for traverse group
$travRights = [System.Security.AccessControl.FileSystemRights]"ReadAndExecute,Synchronize"
$travInheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::None
$travPropagationFlag = [System.Security.AccessControl.PropagationFlags]::None
$travType = [System.Security.AccessControl.AccessControlType]::Allow

# Split up paths and pull the root
$spath = $Path.Split("\")
$qpath = Split-Path -Path $Path -Qualifier
$Paths = New-Object System.Collections.ArrayList

# Build a list of all the directories that lead to the target directory
for($i = 0; $i -le $spath.Length; $i++) {
    if($spath[$i] -ne $null) {
        $PathToAdd = ""
        for($j = 0; $j -le $i; $j++) {
            $PathToAdd += "$($spath[$j])\"
        }
        $Paths.Add($PathToAdd) | Out-Null
    }
}

foreach($item in $Paths) {
    $itemacl = Get-Acl -Path $item
    Write-Verbose $item
    foreach($acl in $itemacl.Access) {
        if(($acl.InheritanceFlags -eq $travInheritanceFlag) -and ($acl.PropagationFlags -eq $travPropagationFlag) -and ($acl.FileSystemRights -eq $travRights) -and ($acl.AccessControlType -eq $travType)) {
            Write-Verbose "Potential traverse group: $($acl.IdentityReference)"
			$SamAccountName = $acl.IdentityReference.ToString().Split("\")[1]
			if($null -ne $SamAccountName) {
				Write-Verbose "Testing AD Permissions: $SamAccountName"
				$ADObject = Get-ADGroup -Identity $SamAccountName
				if($ADObject -ne $null) {
					
				}
			}
        }
    }
}