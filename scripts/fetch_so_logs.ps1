<#
.SYNOPSIS
  Copies recent Suricata eve.json logs from the Security Onion VM to .\so-logs\suricata\
  so the AI assistant / web panel can analyse them ("files" source mode).

.EXAMPLE
  .\scripts\fetch_so_logs.ps1 -SoUser alpkcgl_            # last 24 hours
  .\scripts\fetch_so_logs.ps1 -SoUser alpkcgl_ -Hours 72

.NOTES
  * Uses the OpenSSH client that ships with Windows 10/11 (ssh / scp) and the built-in tar.
  * You will be asked for the Linux password a few times (ssh, sudo, scp). An SSH key avoids that.
  * Security Onion 3 EVAL uses Suricata as metadata engine: eve.json holds alerts, flows, DNS and DHCP.
  * eve file names contain ':' (eve-2026-11-28-12:16.json), which Windows does not allow,
    so they are renamed on the sensor before copying.
#>
param(
    [string]$SoHost = "192.168.1.250",
    [Parameter(Mandatory = $true)][string]$SoUser,
    [int]$Hours = 24
)
$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
$dest = Join-Path $repo "so-logs\suricata"
New-Item -ItemType Directory -Force -Path $dest | Out-Null
$minutes = $Hours * 60

$remote = @"
set -e
rm -rf /tmp/homesiem && mkdir -p /tmp/homesiem
sudo find /nsm/suricata -maxdepth 1 -name 'eve*.json*' -mmin -$minutes | while read -r f; do
  sudo cp "`$f" "/tmp/homesiem/`$(basename "`$f" | tr ':' '-')"
done
sudo chown -R `$(id -un) /tmp/homesiem
tar czf /tmp/homesiem-eve.tgz -C /tmp/homesiem .
rm -rf /tmp/homesiem
ls -lh /tmp/homesiem-eve.tgz
"@ -replace "`r", ""

Write-Host "==> Packing eve.json files of the last $Hours h on $SoHost (sudo password may be asked)"
ssh -t "$SoUser@$SoHost" $remote
Write-Host "==> Copying archive"
scp "${SoUser}@${SoHost}:/tmp/homesiem-eve.tgz" "$dest\"
ssh "$SoUser@$SoHost" "rm -f /tmp/homesiem-eve.tgz"
Write-Host "==> Extracting into $dest"
tar -xzf (Join-Path $dest "homesiem-eve.tgz") -C $dest
Remove-Item (Join-Path $dest "homesiem-eve.tgz")
Get-ChildItem $dest -Filter "eve*" | Format-Table Name, @{n = "MB"; e = { [math]::Round($_.Length / 1MB, 1) } }
Write-Host "Done. config/config.yaml -> source.files.suricata_eve: ../so-logs/suricata/eve*.json"
