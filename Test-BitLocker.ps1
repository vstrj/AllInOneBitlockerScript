#====================================================================================================
#                                             Parameters
#====================================================================================================
#region Parameters

[cmdletbinding()]
param(
  [parameter()]
  [ValidateNotNullOrEmpty()]
  [string]
  $OSDrive = $env:SystemDrive,

  [parameter()]
  [string]
  [ValidateSet('XtsAes256', 'XtsAes128', 'Aes256', 'Aes128')]
  $encryption_strength = 'XtsAes256'
)

#endregion Parameters

#====================================================================================================
#                                           Initialize
#====================================================================================================
#region  Initialize

# Provision new source for Event log
New-EventLog -LogName Application -Source 'Compliance Bitlocker Encryption Script' -ErrorAction SilentlyContinue

#endregion  Initialize

#====================================================================================================
#                                             Functions
#====================================================================================================
#region Functions

function Write-EventLogEntry {
  
  <#
    .Description
      Writes messages and errors to the application event log to be viewed in Event Viewer
  #>

  param (
    [parameter(Mandatory, HelpMessage = 'Add help message for user', Position = 0)]
    [String]
    $Message,
    [parameter(Position = 1)]
    [string]
    [ValidateSet('Information', 'Error')]
    $type = 'Information'
  )

  # Specify Parameters
  $log_params = @{
    Logname   = 'Application'
    Source    = 'Compliance Bitlocker Encryption Script'
    Entrytype = $type
    EventID   = $(
      if ($type -eq 'Information') {
        Write-Output -InputObject 500 
      }
      else {
        Write-Output -InputObject 501 
      }
    )
    Message   = $Message
  }
  
  Write-EventLog @log_params

}

function Test-UsedSpaceEncryption {

  [CmdletBinding()]
  param(
    [Parameter()]
    [String] $BDEusedSpaceEncryption = [bool](manage-bde -status $ENV:SystemDrive | Select-String "Used Space Only Encrypted").Count,
    [Parameter()]
    [String] $BDfullEncryption = [bool](manage-bde -status $ENV:SystemDrive | Select-String "Fully Encrypted").Count
  )

  if ($BDEusedSpaceEncryption -eq $true) {
    Write-EventLogEntry -Message ('Bitlocker is enabled on {0} but the The Drive is in used space encryption' -f $OSDrive)
    $false  
  }
    elseif ($BDfullEncryption -eq $true) {
      Write-EventLogEntry -Message ('Bitlocker is enabled on {0} and the encryption method is set to Fully Encrypted')
      $true
    }
    else {
      Write-EventLogEntry -Message ('Could not determine Encryption Method') 
    }
}





#endregion Functions


#====================================================================================================
#                                             Main-Code
#====================================================================================================

#region MainCode

# Start
Write-EventLogEntry -Message 'Running bitlocker intune encryption script'

# Get bitlocker status
$OSDrive = $ENV:SystemDrive
$BitlockerVolume = Get-BitLockerVolume -MountPoint $ENV:SystemDrive

$encryptionStatus = Test-UsedSpaceEncryption

# Check if OS drive is ecrpyted with parameter $encryption_strength
if ($BitlockerVolume.VolumeStatus -eq 'FullyEncrypted' -and $BitlockerVolume.EncryptionMethod -eq $encryption_strength -and $encryptionStatus) {
  Write-EventLogEntry -Message ('BitLocker is already enabled on {0} and the encryption method is correct and Fully Encrypted' -f $OSDrive)

  return $true
}

elseif ($BitlockerVolume.VolumeStatus -eq 'FullyEncrypted' -and $BitlockerVolume.EncryptionMethod -eq $encryption_strength -and -not $encryptionStatus ) {
  Write-EventLogEntry -Message ('Bitlocker is enabled on {0} but the encryption method does not meet set requirements. Bitlocker On, AES256, Used Space Only' -f $OSDrive)
  return $false
  }



elseif ($BitlockerVolume.VolumeStatus -eq 'FullyEncrypted' -and $BitlockerVolume.EncryptionMethod -ne $encryption_strength) {
  Write-EventLogEntry -Message ('Bitlocker is enabled on {0} but the encryption method does not meet set requirements' -f $OSDrive)
  return $false
  }

elseif ($BitlockerVolume.VolumeStatus -eq 'FullyDecrypted') {
  Write-EventLogEntry -Message ('Bitlocker is enabled on {0} but the encryption method does not meet set requirements' -f $OSDrive)
  return $false
  }



#endregion MainCode