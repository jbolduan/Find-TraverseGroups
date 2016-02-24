<#
	.SYNOPSIS
		Takes in a path and returns the groups with traverse rights on each folder.
	
	.DESCRIPTION
		The script takes in a path as a string.  It then builds a list of paths to the specific path and checks
		each of the directories for groups with read rights defined to "this folder only" and then returns an array
		of groups with an added property for the folder path they exist on.

	.PARAMETER Path
		A string representing the path you would like to get traverse groups for.

	.EXAMPLE
		Find-TraverseGroups -Path "\\fileshare\foo\bar"

	.NOTES
		Created By: Jeff Bolduan
		Last Updated: 2/24/2016
		Function: Find-TraverseGroups
#>
[CmdletBinding()]
param(
	[Parameter(Mandatory=$true)][string]$Path
)

# Import active directory module
Import-Module ActiveDirectory

$TraverseGroups = @()

# Build tests for traverse group
$travRights = [System.Security.AccessControl.FileSystemRights]"ReadAndExecute,Synchronize"
$travInheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::None
$travPropagationFlag = [System.Security.AccessControl.PropagationFlags]::None
$travType = [System.Security.AccessControl.AccessControlType]::Allow

# Get the root of the path
if($Path.StartsWith("\\")) {
	$RootPath = "\\" + [string]::Join("\",$Path.Split("\")[2])
} else {
	$RootPath = Split-Path -Path $Path -Qualifier
}

# Split up paths and pull the root
$spath = $Path.Replace("$RootPath\", "").Split("\")
$Paths = New-Object System.Collections.ArrayList

# Build a list of all the directories that lead to the target directory
for($i = 0; $i -le $spath.Length; $i++) {
	if($spath[$i] -ne $null) {
		$PathToAdd = ""
		for($j = 0; $j -le $i; $j++) {
			$PathToAdd += "$($spath[$j])\"
		}
		# Add the new path to our list of paths
		$Paths.Add("$RootPath\$PathToAdd") | Out-Null
	}
}

# Loop through the paths and determine which contain a traverse group
foreach($item in $Paths) {
	$itemacl = Get-Acl -Path $item
		foreach($acl in $itemacl.Access) {
		# Check the acl for the traverse permissions defined earlier
		if(($acl.InheritanceFlags -eq $travInheritanceFlag) -and ($acl.PropagationFlags -eq $travPropagationFlag) -and ($acl.FileSystemRights -eq $travRights) -and ($acl.AccessControlType -eq $travType) -and ($acl.IsInherited -eq $false)) {
			# We've now found a traverse group
			$SamAccountName = $acl.IdentityReference.ToString().Split("\")[1]

			# Make sure the account name isn't null, then get the group make sure it exists in AD then add the path to the group output object.
			if($null -ne $SamAccountName) {
				$ADObject = Get-ADGroup -Identity $SamAccountName
				if($ADObject -ne $null) {
					$TraverseGroups += $ADObject | Add-Member -MemberType NoteProperty -Name TraversePath -Value $item -Force -PassThru
				}
			}
		}
	}
}

return $TraverseGroups