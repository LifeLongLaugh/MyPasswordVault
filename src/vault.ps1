<#
Personal PowerShell Password Vault
#>

# ================================
# 1. Configuration
# ================================

$ScriptFolder = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootFolder   = Split-Path -Parent $ScriptFolder
$DataFolder   = Join-Path $RootFolder "data"
$VaultFile    = Join-Path $DataFolder "vault.enc"

$script:KeepRunning = $true
$script:MasterKey = $null
$script:VaultSalt = $null
$script:VaultUnlocked = $false

# ================================
# 2. Master Password Helpers
# ================================

function ConvertTo-PlainText {
	param (
		[System.Security.SecureString]$SecureString
	)

	$bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)

	try {
		return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
	}
	finally {
		[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
	}
}

function Read-MasterPassword {
	Write-Host ""
	$securePassword = Read-Host "Enter master password" -AsSecureString
	return $securePassword
}

function New-RandomSalt {
	$salt = New-Object byte[] 32
	$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
	$rng.GetBytes($salt)
	$rng.Dispose()
	return $salt
}

function Get-MasterKey {
	param (
		[string]$Password,
		[byte[]]$Salt
	)

	$iterations = 200000

	$passwordBytes = [System.Text.Encoding]::UTF8.GetBytes($Password)

	$deriveBytes = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
		$passwordBytes,
		$Salt,
		$iterations,
		[System.Security.Cryptography.HashAlgorithmName]::SHA256
	)

	try {
		return $deriveBytes.GetBytes(32)
	}
	finally {
		$deriveBytes.Dispose()
	}
}

# ================================
# 3. Environment Initialization
# ================================

function Initialize-VaultEnvironment {
	if (!(Test-Path $DataFolder)) {
		New-Item -ItemType Directory -Path $DataFolder | Out-Null
	}
}

# ================================
# 4. NTFS Permission Hardening
# ================================

function Protect-VaultStorage {
	try {
		if (!(Test-Path $DataFolder)) {
			return
		}

		$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
		$currentUserSid = $currentUser.User.Value

		Write-Host ""
		Write-Host "Checking vault storage permissions..."

		# Disable inherited permissions on the data folder
		& icacls.exe $DataFolder /inheritance:r | Out-Null

		if ($LASTEXITCODE -ne 0) {
			throw "Unable to disable inherited permissions on data folder."
		}

		# Grant permissions using well-known SIDs:
		# Current user SID
		# SYSTEM = S-1-5-18
		# Administrators = S-1-5-32-544
		$userGrant = "*$($currentUserSid):(OI)(CI)F"
		$systemGrant = "*S-1-5-18:(OI)(CI)F"
		$adminGrant = "*S-1-5-32-544:(OI)(CI)F"

		& icacls.exe $DataFolder /grant:r $userGrant $systemGrant $adminGrant | Out-Null

		if ($LASTEXITCODE -ne 0) {
			throw "Unable to apply restricted permissions on data folder."
		}

		Write-Host "Vault storage permissions hardened." -ForegroundColor Green
	}
	catch {
		Write-Host ""
		Write-Host "WARNING: Could not fully harden NTFS permissions." -ForegroundColor Yellow
		Write-Host "Reason: $($_.Exception.Message)" -ForegroundColor Yellow
		Write-Host "Vault will continue using DPAPI + master password encryption." -ForegroundColor Yellow
	}
}

# ================================
# 5. Validation Helpers
# ================================

function Test-RequiredValue {
	param (
		[string]$Value,
		[string]$FieldName
	)

	if ([string]::IsNullOrWhiteSpace($Value)) {
		Write-Host "$FieldName cannot be empty." -ForegroundColor Yellow
		return $false
	}

	return $true
}

function Test-DuplicateTitle {
	param (
		[array]$VaultData,
		[string]$Title,
		[int]$ExcludeIndex = -1
	)

	if ($null -eq $VaultData) {
		return $false
	}

	$cleanTitle = $Title.Trim()

	for ($i = 0; $i -lt $VaultData.Count; $i++) {
		if ($i -eq $ExcludeIndex) {
			continue
		}

		if ($VaultData[$i].title.Trim() -ieq $cleanTitle) {
			return $true
		}
	}

	return $false
}

# ================================
# 6. Read / Decrypt Vault
# ================================

function Read-Vault {
	if (!(Test-Path $VaultFile)) {
		Write-Host ""
		Write-Host "No vault found. A new master password will be created." -ForegroundColor Yellow

		$masterSecure = Read-MasterPassword
		$masterPlain = ConvertTo-PlainText -SecureString $masterSecure

		if ([string]::IsNullOrWhiteSpace($masterPlain)) {
			Write-Host "Master password cannot be empty. Exiting." -ForegroundColor Red
			exit 1
		}

		$salt = New-RandomSalt
		$masterKey = Get-MasterKey -Password $masterPlain -Salt $salt

		$script:MasterKey = $masterKey
		$script:VaultSalt = $salt
		$script:VaultUnlocked = $true

		return @()
	}

	try {
		$outerEncrypted = (Get-Content $VaultFile -Raw).Trim()

		if ([string]::IsNullOrWhiteSpace($outerEncrypted)) {
			Write-Host "Vault file is empty. Exiting." -ForegroundColor Red
			exit 1
		}

		# Outer decrypt using Windows DPAPI
		$outerSecureString = $outerEncrypted | ConvertTo-SecureString -ErrorAction Stop

		$bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($outerSecureString)

		try {
			$packageJson = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
		}
		finally {
			[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
		}

		$package = $packageJson | ConvertFrom-Json -ErrorAction Stop

		if ($package.version -ne 2) {
			Write-Host ""
			Write-Host "Unsupported vault format. Exiting." -ForegroundColor Red
			exit 1
		}

		$salt = [Convert]::FromBase64String($package.salt)

		$masterSecure = Read-MasterPassword
		$masterPlain = ConvertTo-PlainText -SecureString $masterSecure

		if ([string]::IsNullOrWhiteSpace($masterPlain)) {
			Write-Host "Master password cannot be empty. Exiting." -ForegroundColor Red
			exit 1
		}

		$masterKey = Get-MasterKey -Password $masterPlain -Salt $salt

		# Inner decrypt using master password key
		$innerSecureString = $package.data | ConvertTo-SecureString -Key $masterKey -ErrorAction Stop

		$innerBstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($innerSecureString)

		try {
			$vaultJson = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($innerBstr)
		}
		finally {
			[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($innerBstr)
		}

		if ([string]::IsNullOrWhiteSpace($vaultJson)) {
			return @()
		}

		$vaultData = $vaultJson | ConvertFrom-Json -ErrorAction Stop

		$script:MasterKey = $masterKey
		$script:VaultSalt = $salt
		$script:VaultUnlocked = $true

		if ($null -eq $vaultData) {
			return @()
		}

		return @($vaultData)
	}
	catch {
		Write-Host ""
		Write-Host "ERROR: Unable to open the vault." -ForegroundColor Red
		Write-Host "Possible reasons:"
		Write-Host "- Wrong master password."
		Write-Host "- The vault file was modified manually."
		Write-Host "- The vault file belongs to another Windows user."
		Write-Host "- The vault file is corrupted."
		Write-Host ""
		Write-Host "Vault will now close for safety." -ForegroundColor Yellow
		exit 1
	}
}

# ================================
# 7. Save / Encrypt Vault
# ================================

function Save-Vault {
	param (
		[array]$VaultData,
		[byte[]]$MasterKey,
		[byte[]]$Salt
	)

	if ($null -eq $VaultData) {
		$VaultData = @()
	}

	if ($null -eq $MasterKey -or $null -eq $Salt -or $script:VaultUnlocked -ne $true) {
		Write-Host ""
		Write-Host "ERROR: Vault is not unlocked. Save operation blocked." -ForegroundColor Red
		return $false
	}

	try {
		$vaultJson = ConvertTo-Json -InputObject @($VaultData) -Depth 5

		# Inner encryption using master password derived key
		$innerSecureString = ConvertTo-SecureString $vaultJson -AsPlainText -Force
		$innerEncrypted = $innerSecureString | ConvertFrom-SecureString -Key $MasterKey

		$package = [PSCustomObject]@{
			version    = 2
			kdf		= "PBKDF2-SHA256"
			iterations = 200000
			salt       = [Convert]::ToBase64String($Salt)
			data       = $innerEncrypted
		}

		$packageJson = $package | ConvertTo-Json -Depth 5

		# Outer encryption using Windows DPAPI
		$outerSecureString = ConvertTo-SecureString $packageJson -AsPlainText -Force
		$outerEncrypted = $outerSecureString | ConvertFrom-SecureString

		Set-Content -Path $VaultFile -Value $outerEncrypted -NoNewline

		Write-Host ""
		Write-Host "Vault saved securely." -ForegroundColor Green

		return $true
	}
	catch {
		Write-Host ""
		Write-Host "ERROR: Unable to save the vault." -ForegroundColor Red
		Write-Host $_.Exception.Message
		return $false
	}
}

# ================================
# 8. Show Entry Titles
# ================================

function Show-VaultTitles {
	param (
		[array]$VaultData
	)

	if ($null -eq $VaultData) {
		$VaultData = @()
	}

	if ($VaultData.Count -eq 0) {
		Write-Host ""
		Write-Host "No entries found in the vault." -ForegroundColor Yellow
		return
	}

	Write-Host ""
	Write-Host "Saved Entries"
	Write-Host "-------------"

	for ($i = 0; $i -lt $VaultData.Count; $i++) {
		Write-Host "$($i + 1). $($VaultData[$i].title)"
	}
}

function Select-VaultEntryIndex {
	param (
		[array]$VaultData
	)

	if ($null -eq $VaultData -or $VaultData.Count -eq 0) {
		Write-Host ""
		Write-Host "No entries found in the vault." -ForegroundColor Yellow
		return $null
	}

	Show-VaultTitles -VaultData $VaultData

	Write-Host ""
	Write-Host "Enter 0 to cancel and return to the main menu."
	$selection = Read-Host "Select entry number"

	if ($selection -notmatch '^\d+$') {
		Write-Host "Invalid selection. Please enter a valid number." -ForegroundColor Yellow
		return $null
	}

	$selectedNumber = [int]$selection

	if ($selectedNumber -eq 0) {
		Write-Host "Selection cancelled." -ForegroundColor Yellow
		return $null
	}

	$index = $selectedNumber - 1

	if ($index -lt 0 -or $index -ge $VaultData.Count) {
		Write-Host "Invalid selection. Entry number does not exist." -ForegroundColor Yellow
		return $null
	}

	return $index
}

# ================================
# 9. Clipboard Helper Function
# ================================

function Copy-TextToClipboard {
	param (
		[string]$Text,
		[string]$SuccessMessage
	)

	try {
		Set-Clipboard -Value $Text
		Write-Host ""
		Write-Host $SuccessMessage -ForegroundColor Green
		Write-Host "Clipboard will clear automatically in 15 seconds." -ForegroundColor DarkGray

		# Clear the clipboard after 15 seconds, but only if it still holds
		# the value we just copied (so we don't wipe something newer).
		Start-Job -ScriptBlock {
			param($CopiedText)
			Start-Sleep -Seconds 15
			try {
				$current = Get-Clipboard -Raw -ErrorAction SilentlyContinue
				if ($current -eq $CopiedText) {
					Set-Clipboard -Value ""
				}
			}
			catch {}
		} -ArgumentList $Text | Out-Null
	}
	catch {
		Write-Host ""
		Write-Host "ERROR: Could not copy value to clipboard." -ForegroundColor Red
	}
}

# ================================
# 10. URL Open Helper
# ================================

function Open-EntryUrl {
	param (
		[string]$Url
	)

	if ([string]::IsNullOrWhiteSpace($Url)) {
		Write-Host ""
		Write-Host "URL is empty. Cannot open browser." -ForegroundColor Yellow
		return
	}

	try {
		Start-Process $Url
		Write-Host ""
		Write-Host "URL opened in default browser." -ForegroundColor Green
	}
	catch {
		Write-Host ""
		Write-Host "ERROR: Could not open URL." -ForegroundColor Red
		Write-Host "URL: $Url"
	}
}

# ================================
# 11. View Selected Entry
# ================================

function View-VaultEntry {
	param (
		[array]$VaultData
	)

	$index = Select-VaultEntryIndex -VaultData $VaultData

	if ($null -eq $index) {
		return
	}

	$entry = $VaultData[$index]

	while ($true) {
		Write-Host ""
		Write-Host "Selected Entry"
		Write-Host "--------------"
		Write-Host "Title    : $($entry.title)"
		Write-Host "Username : $($entry.username)"
		Write-Host "URL      : $($entry.url)"

		Write-Host ""
		Write-Host "Entry Actions"
		Write-Host "-------------"
		Write-Host "1. Copy password to clipboard"
		Write-Host "2. Copy username to clipboard"
		Write-Host "3. Open URL in browser"
		Write-Host "4. Back to main menu"
		Write-Host ""

		$action = Read-Host "Choose action"

		switch ($action) {
			"1" {
				Copy-TextToClipboard -Text $entry.password -SuccessMessage "Password copied to clipboard."
			}

			"2" {
				Copy-TextToClipboard -Text $entry.username -SuccessMessage "Username copied to clipboard."
			}

			"3" {
				Open-EntryUrl -Url $entry.url
			}

			"4" {
				return
			}

			default {
				Write-Host ""
				Write-Host "Invalid option. Please choose 1, 2, 3, or 4." -ForegroundColor Yellow
			}
		}
	}
}

# ================================
# 12. Add New Entry
# ================================

function Add-VaultEntry {
	param (
		[array]$VaultData
	)

	if ($null -eq $VaultData) {
		$VaultData = @()
	}

	Write-Host ""
	Write-Host "Add New Entry"
	Write-Host "-------------"

	$title = (Read-Host "Enter title").Trim()

	if (!(Test-RequiredValue -Value $title -FieldName "Title")) {
		Write-Host "Entry not added." -ForegroundColor Yellow
		return @($VaultData)
	}

	if (Test-DuplicateTitle -VaultData $VaultData -Title $title) {
		Write-Host "An entry with this title already exists. Entry not added." -ForegroundColor Yellow
		return @($VaultData)
	}

	$username = (Read-Host "Enter username").Trim()
	if (!(Test-RequiredValue -Value $username -FieldName "Username")) {
		Write-Host "Entry not added." -ForegroundColor Yellow
		return @($VaultData)
	}

	$passwordSecure = Read-Host "Enter password" -AsSecureString
	$password = ConvertTo-PlainText -SecureString $passwordSecure
	if (!(Test-RequiredValue -Value $password -FieldName "Password")) {
		Write-Host "Entry not added." -ForegroundColor Yellow
		return @($VaultData)
	}

	$url = (Read-Host "Enter URL").Trim()
	if (!(Test-RequiredValue -Value $url -FieldName "URL")) {
		Write-Host "Entry not added." -ForegroundColor Yellow
		return @($VaultData)
	}

	$newEntry = [PSCustomObject]@{
		title    = $title
		username = $username
		password = $password
		url      = $url
	}

	$updatedVault = @($VaultData) + $newEntry

	$saveResult = Save-Vault -VaultData $updatedVault -MasterKey $script:MasterKey -Salt $script:VaultSalt

	if ($saveResult -eq $true) {
		Write-Host "Entry added successfully." -ForegroundColor Green
		return @($updatedVault)
	}
	else {
		Write-Host "Entry was not added because the vault could not be saved." -ForegroundColor Red
		return @($VaultData)
	}
}

# ================================
# 13. Edit Existing Entry
# ================================

function Edit-VaultEntry {
	param (
		[array]$VaultData
	)

	if ($null -eq $VaultData) {
		$VaultData = @()
	}

	$index = Select-VaultEntryIndex -VaultData $VaultData

	if ($null -eq $index) {
		return @($VaultData)
	}

	$entry = $VaultData[$index]

	Write-Host ""
	Write-Host "Editing Entry"
	Write-Host "-------------"
	Write-Host "Title    : $($entry.title)"
	Write-Host "Username : $($entry.username)"
	Write-Host "URL      : $($entry.url)"
	Write-Host ""
	Write-Host "Note: Press Enter without typing anything to keep the current value."

	$newUsername = Read-Host "New username"
	if ([string]::IsNullOrWhiteSpace($newUsername)) {
		$newUsername = $entry.username
	}
	else {
		$newUsername = $newUsername.Trim()
	}

	$newPasswordSecure = Read-Host "New password" -AsSecureString
	$newPassword = ConvertTo-PlainText -SecureString $newPasswordSecure
	if ([string]::IsNullOrWhiteSpace($newPassword)) {
		$newPassword = $entry.password
	}

	$newUrl = Read-Host "New URL"
	if ([string]::IsNullOrWhiteSpace($newUrl)) {
		$newUrl = $entry.url
	}
	else {
		$newUrl = $newUrl.Trim()
	}

	if (!(Test-RequiredValue -Value $newUsername -FieldName "Username")) {
		Write-Host "Entry not updated." -ForegroundColor Yellow
		return @($VaultData)
	}

	if (!(Test-RequiredValue -Value $newPassword -FieldName "Password")) {
		Write-Host "Entry not updated." -ForegroundColor Yellow
		return @($VaultData)
	}

	if (!(Test-RequiredValue -Value $newUrl -FieldName "URL")) {
		Write-Host "Entry not updated." -ForegroundColor Yellow
		return @($VaultData)
	}

	Write-Host ""
	Write-Host "Proposed Updated Entry"
	Write-Host "----------------------"
	Write-Host "Title    : $($entry.title)"
	Write-Host "Username : $newUsername"
	Write-Host "URL      : $newUrl"
	Write-Host ""
	Write-Host "Password will be updated but will not be displayed."

	$confirm = Read-Host "Type YES to save these changes"

	if ($confirm -ne "YES") {
		Write-Host "Edit cancelled. No changes saved." -ForegroundColor Yellow
		return @($VaultData)
	}

	$VaultData[$index].username = $newUsername
	$VaultData[$index].password = $newPassword
	$VaultData[$index].url      = $newUrl

	# FIXED: Capture the output of Save-Vault so it doesn't bleed into the return array
	$saveResult = Save-Vault -VaultData $VaultData -MasterKey $script:MasterKey -Salt $script:VaultSalt

	if ($saveResult) {
		Write-Host "Entry updated successfully." -ForegroundColor Green
	}

	return @($VaultData)
}

# ================================
# 14. Rename Entry Title
# ================================

function Rename-VaultEntryTitle {
	param (
		[array]$VaultData
	)

	if ($null -eq $VaultData) {
		$VaultData = @()
	}

	$index = Select-VaultEntryIndex -VaultData $VaultData

	if ($null -eq $index) {
		return @($VaultData)
	}

	$entry = $VaultData[$index]

	Write-Host ""
	Write-Host "Rename Entry Title"
	Write-Host "------------------"
	Write-Host "Current title: $($entry.title)"

	$newTitle = (Read-Host "Enter new title").Trim()

	if (!(Test-RequiredValue -Value $newTitle -FieldName "Title")) {
		Write-Host "Title not renamed." -ForegroundColor Yellow
		return @($VaultData)
	}

	if ($newTitle -ieq $entry.title.Trim()) {
		Write-Host "New title is same as current title. Rename cancelled. No changes saved." -ForegroundColor Yellow
		return @($VaultData)
	}

	if (Test-DuplicateTitle -VaultData $VaultData -Title $newTitle -ExcludeIndex $index) {
		Write-Host "An entry with this title already exists. Title not renamed." -ForegroundColor Yellow
		return @($VaultData)
	}

	Write-Host ""
	Write-Host "Old title: $($entry.title)"
	Write-Host "New title: $newTitle"

	$confirm = Read-Host "Type YES to rename this entry"

	if ($confirm -ne "YES") {
		Write-Host "Rename cancelled. No changes saved." -ForegroundColor Yellow
		return @($VaultData)
	}

	$VaultData[$index].title = $newTitle

	# FIXED: Capture the output of Save-Vault here as well
	$saveResult = Save-Vault -VaultData $VaultData -MasterKey $script:MasterKey -Salt $script:VaultSalt

	if ($saveResult) {
		Write-Host "Title renamed successfully." -ForegroundColor Green
	}

	return @($VaultData)
}

# ================================
# 15. Delete Entry
# ================================

function Remove-VaultEntry {
	param (
		[array]$VaultData
	)

	if ($null -eq $VaultData) {
		$VaultData = @()
	}

	$index = Select-VaultEntryIndex -VaultData $VaultData

	if ($null -eq $index) {
		return @($VaultData)
	}

	$entry = $VaultData[$index]

	Write-Host ""
	Write-Host "Delete Entry"
	Write-Host "------------"
	Write-Host "Title    : $($entry.title)"
	Write-Host "Username : $($entry.username)"
	Write-Host "URL      : $($entry.url)"
	Write-Host ""
	Write-Host "WARNING: This action cannot be undone." -ForegroundColor Yellow

	$confirm = Read-Host "Type DELETE to permanently delete this entry"

	if ($confirm -ine "DELETE") {
		Write-Host "Delete cancelled. No changes saved." -ForegroundColor Yellow
		return @($VaultData)
	}

	$updatedVault = @()

	for ($i = 0; $i -lt $VaultData.Count; $i++) {
		if ($i -ne $index) {
			$updatedVault += $VaultData[$i]
		}
	}

	$saveResult = Save-Vault -VaultData $updatedVault -MasterKey $script:MasterKey -Salt $script:VaultSalt

	if ($saveResult -eq $true) {
		Write-Host "Entry deleted successfully." -ForegroundColor Green
		return @($updatedVault)
	}
	else {
		Write-Host "Entry was not deleted because the vault could not be saved." -ForegroundColor Red
		return @($VaultData)
	}
}

# ================================
# 16. Exit Vault
# ================================

function Stop-Vault {
	Write-Host ""
	Write-Host "Exiting vault."
	$script:KeepRunning = $false
}

# ================================
# 17. Main Menu
# ================================

function Show-MainMenu {
	Write-Host ""
	Write-Host "================================"
	Write-Host " Personal Password Vault"
	Write-Host "================================"
	Write-Host "1. View saved entries"
	Write-Host "2. Add new entry"
	Write-Host "3. Edit existing entry"
	Write-Host "4. Rename entry title"
	Write-Host "5. Delete entry"
	Write-Host "6. Exit"
	Write-Host ""
}

# ================================
# 18. Main Program
# ================================

Initialize-VaultEnvironment
Protect-VaultStorage

$vault = @(Read-Vault)

if ($null -eq $vault) {
	$vault = @()
}

while ($script:KeepRunning) {
	Show-MainMenu

	$choice = Read-Host "Choose option"

	switch ($choice) {
		"1" {
			View-VaultEntry -VaultData $vault
		}

		"2" {
			$vault = @(Add-VaultEntry -VaultData $vault)
		}

		"3" {
			$vault = @(Edit-VaultEntry -VaultData $vault)
		}

		"4" {
			$vault = @(Rename-VaultEntryTitle -VaultData $vault)
		}

		"5" {
			$vault = @(Remove-VaultEntry -VaultData $vault)
		}

		"6" {
			Stop-Vault
		}

		default {
			Write-Host ""
			Write-Host "Invalid option. Please choose 1, 2, 3, 4, or 5." -ForegroundColor Yellow
		}
	}
}

Get-Job | Remove-Job -Force -ErrorAction SilentlyContinue