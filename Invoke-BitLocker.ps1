#====================================================================================================
#                                             Parameters
#====================================================================================================
#region Parameters

[cmdletbinding()]
param(
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
New-EventLog -LogName Application -Source 'Full Bitlocker Encryption Script 4.0' -ErrorAction SilentlyContinue

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
    Source    = 'Full Bitlocker Encryption Script 4.0'
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

function Get-TPMStatus {
  
  <#
    .Description
      Checks the TPM is present and ready and returns True, or returns False if either condtion fails.
  #>
  
  [cmdletbinding()]
  param(
    [psobject]
    $tpm = (Get-TPM)
  )
  
  if ($tpm.TpmReady -and $tpm.TpmPresent -eq $true) {
    $true
  }
  else {
    $false
  }
}

function Test-RecoveryPasswordProtector {
  
  <#
    .Description
      Check if recovery password protector is present and return true if present or false if not.
  #>
  
  [cmdletbinding()]
  param(
    [parameter(Mandatory)]
    [string]
    $MountPoint
  )

  $AllProtectors = (Get-BitLockerVolume -MountPoint $MountPoint).KeyProtector
  $RecoveryProtector = ($AllProtectors | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' })
  
  if (($RecoveryProtector).KeyProtectorType -eq 'RecoveryPassword') {
      
    Write-EventLogEntry -Message 'Recovery password protector detected'
    $true
    
  }
  
  else {
    
    Write-EventLogEntry -Message 'Recovery password protector not detected'
    $false
    
  }

}

function Test-TpmProtector {
  
  <#
    .Description
      Check if a TPM protector is present and return true if present or false if not.
  #>
  
  [cmdletbinding()]
  param(
    [parameter(Mandatory)]
    [string]
    $MountPoint
  )

  $AllProtectors = (Get-BitLockerVolume -MountPoint $MountPoint).KeyProtector
  $RecoveryProtector = ($AllProtectors | Where-Object { $_.KeyProtectorType -eq 'Tpm' })
  
  if (($RecoveryProtector).KeyProtectorType -eq 'Tpm') {
    
    Write-EventLogEntry -Message 'TPM protector detected'
    $true
  
  }
  
  else {
  
    Write-EventLogEntry -Message 'TPM protector not detected'
    $false
  
  }

}

function Set-RecoveryPasswordProtector {
  
  <#
    .Description
      Add a recovery password protector to a bitlocker enabled volume
  #>
  
  [cmdletbinding()]
  param(
    [parameter(Mandatory)]
    [string]
    $MountPoint
  )

  try {
    Add-BitLockerKeyProtector -MountPoint $MountPoint -RecoveryPasswordProtector 
    Write-EventLogEntry -Message ('Added recovery password protector to bitlocker enabled drive {0}' -f $MountPoint)
  }
  
  catch {
    throw Write-EventLogEntry -Message 'Error adding recovery password protector to bitlocker enabled drive' -type error
  }
}

function Set-TpmProtector {
  
  <#
    .Description
      Add a TPM protector to a bitlocker enabled volume
  #>
  
  [cmdletbinding()]
  param(
    [parameter(Mandatory)]
    [string]
    $MountPoint
  )
  
  try {
    Add-BitLockerKeyProtector -MountPoint $MountPoint -TpmProtector
    Write-EventLogEntry -Message ('Added TPM protector to bitlocker enabled drive {0}' -f $MountPoint)
  }
  
  catch {
    throw Write-EventLogEntry -Message 'Error adding TPM protector to bitlocker enabled drive' -type error
  }
}


function Invoke-Encryption {
  
  <#
    .Description
      Enable bitlocker with specified strength on volume
  #>
  
  [cmdletbinding()]
  param(
    [parameter(Mandatory)]
    [string]
    $MountPoint,

    [parameter(Mandatory)]
    [string]
    $encryption_strength
  )

  # Test that TPM is present and ready
  try {
    Write-EventLogEntry -Message 'Checking TPM Status before attempting encryption'
    
    if (Get-TPMStatus) {
      Write-EventLogEntry -Message 'TPM Present and Ready. Beginning encryption process'
    }
  }
  
  catch {
    throw Write-EventLogEntry -Message 'Issue with TPM. Exiting script' -type error
  }


  # Encrypting OS drive
  try {
    Write-EventLogEntry -Message ('Enabling bitlocker with Recovery Password protector and method {0}' -f $encryption_strength)
    Enable-BitLocker -MountPoint $MountPoint -SkipHardwareTest -EncryptionMethod $encryption_strength -RecoveryPasswordProtector
    Write-EventLogEntry -Message ('Bitlocker enabled on {0} with {1} encryption method' -f $MountPoint, $encryption_strength)
  }
  
  catch {
    throw Write-EventLogEntry -Message ('Error enabling bitlocker on {0}. Exiting script' -f $MountPoint)
  }
}

function Invoke-UnEncryption {
  
  <#
    .Description
      Disable bitlocker and unencrypt volume
  #>
  
  [cmdletbinding()]
  param(
    [parameter(Mandatory)]
    [string]
    $MountPoint
  )
    
  # Call disable-bitlocker command, reboot after unencryption?
  try {
    Write-EventLogEntry -Message ('Unencrypting bitlocker enabled drive {0}' -f $MountPoint)
    Disable-BitLocker -MountPoint $MountPoint
  }
  
  catch {
    throw Write-EventLogEntry -Message ('Issue unencrypting bitlocker enabled drive {0}' -f $MountPoint)
  }
}

function Remove-RecoveryPasswordProtectors {
  
  <#
    .Description
      Remove any password protectors on bitlocker enabled volume
  #>
  
  [cmdletbinding()]
  param(
    [parameter(Mandatory)]
    [string]
    $MountPoint
  )
  
  try {
    $RecoveryPasswordProtectors = (Get-BitLockerVolume -MountPoint $MountPoint).KeyProtector | Where-Object { $_.KeyProtectorType -contains 'RecoveryPassword' }

    foreach ($PasswordProtector in $RecoveryPasswordProtectors) {
      Remove-BitLockerKeyProtector -MountPoint $MountPoint -KeyProtectorId $PasswordProtector.KeyProtectorID
      Write-EventLogEntry -Message ('Removed recovery password protector with ID: {0}' -f ($PasswordProtector.KeyProtectorID))
    }
  }
  
  catch {
    Write-EventLogEntry -Message 'Error removing recovery password protector' -type Error
  }
}

function Remove-TPMProtector { 
  
  <#
    .Description
      Remove TPM protector from bitlocker enable volume
  #>
  
  [cmdletbinding()]
  param(
    [parameter(Mandatory)]
    [string]
    $MountPoint
  )

  # Remove TPM password protector
  try {
    $TPMProtector = (Get-BitLockerVolume -MountPoint $MountPoint).KeyProtector | Where-Object { $_.KeyProtectorType -contains 'Tpm' }
    Remove-BitLockerKeyProtector -MountPoint $MountPoint -KeyProtectorId $TPMProtector.KeyProtectorID
    Write-EventLogEntry -Message ('Removed TPM Protector with ID: {0}' -f ($TPMProtector.KeyProtectorID))
  }
  
  catch {
    Write-EventLogEntry -Message 'Error removing recovery password protector' -type Error
  }
}

function Set-OsEncryptionType {
  [CmdletBinding()]
  param(
    [Parameter()]
    [String] $OSETregistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE",
    [Parameter()]
    [String] $OSETName = "OSEncryptionType",
    [Parameter()]
    [String] $OSETvalue = "1"
  )

  process {
    try {
      if(!(Test-Path $OSETregistryPath))
      {
        New-Item -Path $OSETregistryPath -Force | Out-Null
        New-ItemProperty -Path $OSETregistryPath -Name $OSETname -Value $OSETvalue -Force | Out-Null
        Set-ItemProperty -Path $OSETregistryPath -Name $OSETname -Value $OSETvalue -Type DWord -Force | Out-Null
      }
     else {
        Set-ItemProperty -Path $OSETregistryPath -Name $OSETname -Value $OSETvalue -Type DWord -Force | Out-Null
      }
      Write-EventLogEntry -Message "Changed OSEncryptionType Value in registry to $OSETvalue "
    }
    
    catch {
      #Write-EventLogEntry -Message 'Error removing recovery password protector' -type Error
      Write-EventLogEntry -Message 'Could not change OSEncryptionType Value in registry'
    }
  }
}

#endregion Functions

#====================================================================================================
#                                             Main-Code
#====================================================================================================

#region MainCode

$OSDrive = $ENV:SystemDrive

Set-OsEncryptionType

  try {
    # Decrypt OS drive
    Invoke-UnEncryption -MountPoint $OSDrive
    Write-EventLogEntry -Message ('Decrypt OS drive' -f $OSDrive)
        
    # Wait for decryption to finish 
    Do {
      Start-Sleep -Seconds 30
    }
    until ((Get-BitLockerVolume -MountPoint $OSDrive).VolumeStatus -eq 'FullyDecrypted')
    
    Write-EventLogEntry -Message ('{0} has been fully decrypted' -f $OSDrive)

    # Check for and remove any remaining recovery password protectors
    if (Test-RecoveryPasswordProtector -MountPoint $OSDrive ) {
      
      try {
        Write-EventLogEntry -Message 'Recovery password protector found post decryption. Removing to prevent duplicate entries'
        Remove-RecoveryPasswordProtectors -MountPoint $OSDrive
      }
      
      catch {
        throw Write-EventLogEntry -Message ("Error removing recovery password protect from bitlocker volume {0} exiting script" -f $OSDrive) -type Error
        exit
      }
    }

    # Check for and remaining TPM protector
    if (Test-TpmProtector -MountPoint $OSDrive) {
      
      try {
        Write-EventLogEntry -Message 'TPM protector found post decryption. Removing to prevent encryption issues'
        Remove-TPMProtector -MountPoint $OSDrive
      }
      
      catch {
        throw Write-EventLogEntry -Message ("Error removing TPM protector from bitlocker volume {0} exiting script" -f $OSDrive) -type Error`
      }
    }

    # Trigger encryption with specified encryption method 
    Invoke-Encryption -MountPoint $OSDrive -encryption_strength $encryption_strength
    Start-Sleep -Seconds 5
  }
  
  catch {
    
    throw Write-EventLogEntry -Message ('Failed to encrypt {0} after decryption. Exiting script' -f $OSDrive) -type error
    exit
  
  }

  #endregion MainCode