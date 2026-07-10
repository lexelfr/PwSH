<#
.SYNOPSIS
    Diagnostique les certificats LDAPS, extrait le Thumbprint et les SAN.
.DESCRIPTION
    Ce script se connecte à un serveur via LDAPS (port 636), valide la chaîne de 
    confiance TLS, puis extrait l'empreinte numérique (Thumbprint) et les noms 
    alternatifs (SAN) du certificat sans nécessiter d'outils tiers (comme OpenSSL).
.PARAMETER Server
    Le nom de domaine complet (FQDN) du serveur LDAPS à tester.
.PARAMETER Port
    Le port LDAPS (par défaut : 636).
.EXAMPLE
    .\Test-LdapsCertificate.ps1
    (Exécution interactive avec invite de saisie)
.EXAMPLE
    .\Test-LdapsCertificate.ps1 -Server "dc01.contoso.local" -Port 636
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false, Position = 0)]
    [string]$Server,

    [Parameter(Mandatory = $false)]
    [int]$Port = 636
)

# 1. Gestion interactive si le script est lancé sans paramètres
if ([string]::IsNullOrWhiteSpace($Server)) {
    $DefaultServer = "dc01.contoso.local"
    $Server = Read-Host "Entrez le FQDN du serveur LDAPS [Par défaut: $DefaultServer]"
    if ([string]::IsNullOrWhiteSpace($Server)) { $Server = $DefaultServer }
}

# 2. Forcer l'utilisation de protocoles TLS modernes (1.2 et 1.3)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

$TcpClient = $null
try {
    Write-Host "Connexion à ${Server}:${Port}..." -ForegroundColor Yellow
    
    # 3. Connexion TCP et initialisation du flux SSL/TLS
    $TcpClient = New-Object System.Net.Sockets.TcpClient($Server, $Port)
    
    # Callback pour intercepter les erreurs de validation du certificat sans bloquer le script
    $ValidationCallback = { 
        param($sender, $cert, $chain, $errors) 
        $global:tlsErrors = $errors
        return $true 
    }
    
    $SslStream = New-Object System.Net.Security.SslStream($TcpClient.GetStream(), $true, $ValidationCallback)
    $SslStream.AuthenticateAsClient($Server)
    
    # 4. Extraction et analyse du certificat
    if ($SslStream.RemoteCertificate) {
        $Cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]$SslStream.RemoteCertificate

        # --- Affichage des résultats ---
        Write-Host "`n=========================================" -ForegroundColor Gray
        Write-Host "--- VALIDATION ---" -ForegroundColor Cyan
        
        if ($global:tlsErrors -eq "None") { 
            Write-Host "Connexion TLS : Valide (Certificat de confiance)" -ForegroundColor Green 
        } else { 
            Write-Host "Erreur de validation : $global:tlsErrors" -ForegroundColor Red 
        }

        Write-Host "`n--- THUMBPRINT (SHA1) ---" -ForegroundColor Cyan
        Write-Host $Cert.Thumbprint

        Write-Host "`n--- SAN (Subject Alternative Names) ---" -ForegroundColor Cyan
        # Utilisation de l'OID universel (2.5.29.17) pour assurer la compatibilité toutes langues (FR/EN)
        $SanExtension = $Cert.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.17" }
        if ($SanExtension) {
            Write-Host ($SanExtension.Format($true))
        } else {
            Write-Host "Aucun champ SAN trouvé dans ce certificat." -ForegroundColor Yellow
        }
        Write-Host "=========================================" -ForegroundColor Gray
    } else {
        Write-Error "Impossible de récupérer le certificat du serveur distant."
    }
}
catch {
    Write-Error "Échec de la connexion : $_"
}
finally {
    if ($TcpClient) { 
        $TcpClient.Close() 
    }
}
