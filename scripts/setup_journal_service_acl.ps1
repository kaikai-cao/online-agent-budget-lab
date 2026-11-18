# E1.9-B / B-F2 -- Journal Service private-file isolation (ADMIN deploy step).
#
# Implements the frozen B2 deployment assumption that `e689f7d` left as a doc
# note: the Journal signing key, fixed config, Journal DB and idempotency DB are
# owned/accessible ONLY by the Journal service account, so a compromised
# Executor account can neither read the signing key nor mutate either database.
#
# Run in an ELEVATED PowerShell on the target Windows host.  This script does
# NOT create an HSM/TPM and does NOT protect against an administrator who can
# take ownership of files; it is exactly the OS-ACL boundary from the B2 design.
#
#   powershell -ExecutionPolicy Bypass -File setup_journal_service_acl.ps1 `
#       -JournalServiceAccount 'HOSTNAME\jrnl_svc_acct' `
#       -ExecutorAccount       'HOSTNAME\exec_acct' `
#       -ConfigDir             'C:\ProgramData\OnlineBudget\journal' `
#       -StateDir              'C:\ProgramData\OnlineBudget\journal\state'
#
# It: (1) verifies both accounts exist; (2) creates the directories; (3) grants
# ONLY the journal service account FullControl; (4) removes inherited ACEs;
# (5) explicitly DENIES the Executor account, so a later broad parent-dir grant
# cannot silently re-open the files; (6) prints the service SID for config ACL.

param(
    [Parameter(Mandatory = $true)][string]$JournalServiceAccount,
    [Parameter(Mandatory = $true)][string]$ExecutorAccount,
    [Parameter(Mandatory = $true)][string]$ConfigDir,
    [Parameter(Mandatory = $true)][string]$StateDir
)

$ErrorActionPreference = 'Stop'

function Get-AccountSid {
    param([string]$Name)
    $short = $Name.Split('\')[-1]
    $obj = Get-LocalUser -Name $short -ErrorAction SilentlyContinue
    if ($null -eq $obj) {
        throw "Local account '$Name' not found. Create it first (see the implementation report)."
    }
    return $obj.SID.Value
}

$svcSid  = Get-AccountSid -Name $JournalServiceAccount
$execSid = Get-AccountSid -Name $ExecutorAccount
Write-Host "journal service SID: $svcSid"
Write-Host "executor SID:        $execSid"

New-Item -ItemType Directory -Force -Path $ConfigDir | Out-Null
New-Item -ItemType Directory -Force -Path $StateDir  | Out-Null

function Lock-Dir {
    param([string]$Path, [string]$AllowSid, [string]$DenySid)
    # Reset to a minimal DACL: SYSTEM + Administrators + service account only.
    icacls $Path /inheritance:r /grant:r "*$AllowSid:(OI)(CI)(F)" `
        /grant "*S-1-5-18:(OI)(CI)(F)" "/grant *S-1-5-32-544:(OI)(CI)(F)" `
        /deny  "*$DenySid:(OI)(CI)(RX,D,W)" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls failed on $Path" }
    Write-Host "locked: $Path"
}

Lock-Dir -Path $ConfigDir -AllowSid $svcSid -DenySid $execSid
Lock-Dir -Path $StateDir  -AllowSid $svcSid -DenySid $execSid

Write-Host @'
Private-file isolation applied. Next steps (ADMIN):
  1. Generate the config INSIDE the locked ConfigDir while running as the
     journal service account (or copy it in as ADMIN then re-apply Lock-Dir):
       python -m online_budget.journal_service_main --print-sid
  2. Start the service as the journal service account (service host / scheduled
     task), NOT as the Executor account.
  3. Verify denial: as the Executor account, attempt to read service.json and
     to write journal.sqlite3 -- both must fail (Access is denied).
  4. The service process itself calls journal_fileacl.verify_private_files()
     at startup and refuses to serve if any forbidden SID retains access.
'@
