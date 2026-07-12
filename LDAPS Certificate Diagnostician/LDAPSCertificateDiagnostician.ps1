<#
.SYNOPSIS
    Diagnostique les certificats LDAPS, extrait le Thumbprint et les SAN.
.DESCRIPTION
    Ce script se connecte a un serveur via LDAPS (port 636), valide la chaine de 
    confiance TLS, puis extrait l'empreinte numerique (Thumbprint) et les noms 
    alternatifs (SAN) du certificat sans necessiter d'outils tiers (comme OpenSSL).
    Gere le rebond (Round-Robin) pour tester plusieurs IPs associees au meme nom DNS.
.PARAMETER Server
    Le nom de domaine complet (FQDN) du serveur LDAPS a tester.
.PARAMETER Port
    Le port LDAPS (par defaut : 636).
.PARAMETER Loop
    Si specifie, force l'execution en boucle automatique (utile pour les scripts automatises).
.EXAMPLE
    .\Test-LdapsCertificate.ps1
    (Execution interactive avec invite de saisie et option de rejeu)
.EXAMPLE
    .\Test-LdapsCertificate.ps1 -Server "dc01.contoso.local" -Port 636
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false, Position = 0)]
    [string]$Server,

    [Parameter(Mandatory = $false)]
    [int]$Port = 636,

    [Parameter(Mandatory = $false)]
    [switch]$Loop
)

# 1. Gestion interactive si le script est lance sans parametres
if ([string]::IsNullOrWhiteSpace($Server)) {
    $DefaultServer = "dc01.contoso.local"
    $Server = Read-Host "Entrez le FQDN du serveur LDAPS [Par defaut: $DefaultServer]"
    if ([string]::IsNullOrWhiteSpace($Server)) { $Server = $DefaultServer }
}

# 2. Forcer l'utilisation de protocoles TLS modernes (1.2 et 1.3)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

do {
    $TcpClient = $null
    $global:tlsErrors = $null
    
    try {
        # Resolution DNS pour afficher l'IP ciblee (tres utile en cas de Round-Robin)
        Write-Host "`nResolution DNS pour $Server..." -ForegroundColor Gray
        $TargetIPs = [System.Net.Dns]::GetHostAddresses($Server) | Where-Object { $_.AddressFamily -eq 'InterNetwork' }
        if ($TargetIPs) {
            Write-Host "IPs trouvees pour ce nom : $($TargetIPs -join ', ')" -ForegroundColor Gray
        }

        Write-Host "Connexion a ${Server}:${Port}..." -ForegroundColor Yellow
        
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

            # --- Affichage des resultats ---
            Write-Host "=========================================" -ForegroundColor Gray
            Write-Host "--- VALIDATION ---" -ForegroundColor Cyan
            
            if ($global:tlsErrors -eq "None") { 
                Write-Host "Connexion TLS : Valide (Certificat de confiance)" -ForegroundColor Green 
            } else { 
                Write-Host "Erreur de validation : $global:tlsErrors" -ForegroundColor Red 
            }

            Write-Host "`n--- THUMBPRINT (SHA1) ---" -ForegroundColor Cyan
            Write-Host $Cert.Thumbprint

            Write-Host "`n--- SAN (Subject Alternative Names) ---" -ForegroundColor Cyan
            # Utilisation de l'OID universel (2.5.29.17) pour assurer la compatibilite toutes langues (FR/EN)
            $SanExtension = $Cert.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.17" }
            if ($SanExtension) {
                Write-Host ($SanExtension.Format($true))
            } else {
                Write-Host "Aucun champ SAN trouve dans ce certificat." -ForegroundColor Yellow
            }
            Write-Host "=========================================" -ForegroundColor Gray
        } else {
            Write-Error "Impossible de recuperer le certificat du serveur distant."
        }
    }
    catch {
        Write-Error "Echec de la connexion : $_"
    }
    finally {
        if ($TcpClient) { 
            $TcpClient.Close() 
        }
    }

    # 5. Gestion du Round-Robin / Rejeu (Par defaut : OUI)
    if (-not $Loop) {
        $Response = Read-Host "`nVoulez-vous rejouer le test sur ce nom ? [O/N] (Par defaut: O)"
        
        # Si l'utilisateur tape Entree (vide), ou n'importe quoi commençant par O/Y -> On rejoue.
        # Si l'utilisateur tape explicitement N/n -> On s'arrete.
        if ([string]::IsNullOrWhiteSpace($Response)) {
            $PlayAgain = $true
        } else {
            $PlayAgain = $Response -notmatch '^[nN]'
        }
    } else {
        $PlayAgain = $false
    }

} while ($PlayAgain)