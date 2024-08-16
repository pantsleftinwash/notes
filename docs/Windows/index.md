---
sidebar_position: 2
---

# Windows

## Certificates

```powershell title='Get certificate data'
Get-ChildItem -Path Cert:\LocalMachine\My | ForEach-Object { $cert = $_; $keyType = if ($cert.HasPrivateKey) { $cert.PrivateKey.CspKeyContainerInfo.ProviderName } else { "No Private Key" }; [PSCustomObject]@{FriendlyName = $cert.FriendlyName; Subject = $cert.Subject; Thumbprint = $cert.Thumbprint; KeyType = $keyType } }
```

```powershell title='import a certificate'
$pwd = ConvertTo-SecureString -String "safe" -AsPlainText -Force
Import-PfxCertificate -Password $pwd -FilePath "tokenencryption.pfx" -CertStoreLocation Cert:\LocalMachine\My
```

```powershell title='Remove a Certifcate'
Get-ChildItem Cert:\LocalMachine\My\DD53690E336AAED97D4B3118881C8AF662DBF45E | Remove-Item
```

## Logs

```powershell title='Get detailed logs'
Get-WinEvent -FilterHashtable @{LogName="Application"} -MaxEvents 10 | Select-Object -Property *
```

## Functions

```powershell title='Disable annoying features'
# Windows Update
$pause = (Get-Date).AddDays(365); $pause = $pause.ToUniversalTime().ToString( "yyyy-MM-ddTHH:mm:ssZ" ); Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseUpdatesExpiryTime' -Value $pause
# Windows Error Reporting
Disable-WindowsErrorReporting
# Windfows defender realtime monitoring
Set-MpPreference -DisableRealtimeMonitoring $true
```

```powershell title ='Awkward Debugging
wevtutil sl Application /ms:2097152000
Get-WinEvent -LogName "Application" | Where-Object { $_.Message -like "*GeoFence*" }
```