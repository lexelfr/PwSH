<#
.SYNOPSIS
    Diagnostique les certificats LDAPS sur toutes les IP d'un nom DNS (Round-Robin).
.DESCRIPTION
    Ce script resout un nom DNS, liste toutes les adresses IPv4 associees, puis se
    connecte individuellement a chaque adresse IP sur le port LDAPS (636). Il valide 
    la chaine de confiance TLS, extrait l'empreinte numerique (Thumbprint) et les noms 
    alternatifs (SAN) de chaque controleur de domaine.
.PARAMETER Server
    Le nom de domaine complet (FQDN) du serveur LDAPS ou de la zone Round-Robin a tester.
.PARAMETER Port
    Le port LDAPS (par defaut : 636).
.PARAMETER Loop
    Si specifie, force l'execution en boucle automatique (utile pour les scripts automatises).
.EXAMPLE
    .\Test-LdapsCertificate.ps1
.EXAMPLE
    .\Test-LdapsCertificate.ps1 -Server "themartins.lan" -Port 636
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
    # 3. Resolution DNS globale
    Write-Host "`n[+] Resolution DNS pour $Server..." -ForegroundColor Gray
    try {
        $TargetIPs = [System.Net.Dns]::GetHostAddresses($Server) | Where-Object { $_.AddressFamily -eq 'InterNetwork' }
        if (-not $TargetIPs) {
            Write-Error "Aucune adresse IPv4 trouvee pour le nom : $Server"
            break
        }
        Write-Host "[*] $($TargetIPs.Count) adresse(s) IP trouvee(s) : $($TargetIPs -join ', ')" -ForegroundColor Gray
    }
    catch {
        Write-Error "Impossible de resoudre le nom DNS : $_"
        break
    }

    # 4. Parcours de TOUTES les adresses IP trouvees
    foreach ($IP in $TargetIPs) {
        $TcpClient = $null
        $global:tlsErrors = $null
        
        Write-Host "`n--------------------------------------------------" -ForegroundColor DarkGray
        Write-Host " TEST CIBLE : $Server à l'adresse [$IP]" -ForegroundColor Yellow
        Write-Host "--------------------------------------------------" -ForegroundColor DarkGray
        
        try {
            # Connexion TCP ciblee sur l'IP specifique
            Write-Host "-> Connexion TCP vers $IP sur le port $Port..." -ForegroundColor Gray
            $TcpClient = New-Object System.Net.Sockets.TcpClient
            $TcpClient.Connect($IP, $Port)
            
            # Callback pour intercepter les erreurs sans bloquer le script
            $ValidationCallback = { 
                param($sender, $cert, $chain, $errors) 
                $global:tlsErrors = $errors
                return $true 
            }
            
            # Initialisation SSL/TLS : On passe l'IP pour le flux, mais le Nom DNS ($Server) 
            # pour que la verification du certificat et le SNI restent valides.
            $SslStream = New-Object System.Net.Security.SslStream($TcpClient.GetStream(), $true, $ValidationCallback)
            $SslStream.AuthenticateAsClient($Server)
            
            if ($SslStream.RemoteCertificate) {
                $Cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]$SslStream.RemoteCertificate

                # --- Affichage des resultats pour cette IP ---
                Write-Host "--- VALIDATION ---" -ForegroundColor Cyan
                if ($global:tlsErrors -eq "None") { 
                    Write-Host "Connexion TLS : Valide (Certificat de confiance)" -ForegroundColor Green 
                } else { 
                    Write-Host "Erreur de validation : $global:tlsErrors" -ForegroundColor Red 
                }

                Write-Host "`n--- THUMBPRINT (SHA1) ---" -ForegroundColor Cyan
                Write-Host $Cert.Thumbprint

                Write-Host "`n--- SAN (Subject Alternative Names) ---" -ForegroundColor Cyan
                $SanExtension = $Cert.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.17" }
                if ($SanExtension) {
                    Write-Host ($SanExtension.Format($true))
                } else {
                    Write-Host "Aucun champ SAN trouve dans ce certificat." -ForegroundColor Yellow
                }
            } else {
                Write-Error "[$IP] Impossible de recuperer le certificat du serveur distant."
            }
        }
        catch {
            Write-Error "[$IP] Echec de la connexion ou de la négociation TLS : $_"
        }
        finally {
            if ($TcpClient) { $TcpClient.Close() }
        }
    }

    Write-Host "`n==================================================" -ForegroundColor DarkGray
    Write-Host "Fin de l'analyse pour toutes les adresses IP." -ForegroundColor Gray
    Write-Host "==================================================" -ForegroundColor DarkGray

    # 5. Gestion de la boucle globale de rejeu
    if (-not $Loop) {
        $Response = Read-Host "`nVoulez-vous relancer un scan complet sur ce nom ? [O/N] (Par defaut: O)"
        if ([string]::IsNullOrWhiteSpace($Response)) {
            $PlayAgain = $true
        } else {
            $PlayAgain = $Response -notmatch '^[nN]'
        }
    } else {
        $PlayAgain = $false
    }

} while ($PlayAgain)