# Get-ADHealth - Diagnostic de Santé Active Directory

`Get-ADHealth.ps1` est un script PowerShell complet conçu pour analyser la santé de vos contrôleurs de domaine (DCs) et de votre forêt Active Directory. Il compile l'ensemble des résultats dans un rapport HTML moderne, dynamique et responsive, prêt à être consulté localement ou envoyé par e-mail.

---

## 🌟 Fonctionnalités du Rapport

* **Tableau de Bord Exécutif :** Affiche une synthèse globale en haut du rapport (Total de DCs, DCs en ligne, nombre d'Erreurs et d'Avertissements détectés).
* **Sections Thématiques :** Les diagnostics sont organisés en 9 catégories distinctes pour une lisibilité maximale :
  1. **Identité & Configuration** (Serveur, Site AD, Rôles FSMO, version d'OS)
  2. **Connectivité & Réseau** (Ping, DNS, IPv6, reboot en attente, décalage temporel)
  3. **Performances & Matériel** (Uptime, espace disque détaillé, RAM, CPU)
  4. **Services de Base AD** (DNS, NetLogon, KDC, ADWS)
  5. **Tests DCDIAG** (Connectivity, Advertising, SysVolCheck, Replications, etc.)
  6. **Événements & Journaux** (Warning, Error, Critical et KCC dans les 8 dernières heures)
  7. **Réplication & Partages** (Partages SYSVOL/NETLOGON, latence maximale, erreurs)
  8. **Sécurité & Paramètres Globaux** (Tombstone Lifetime, Corbeille AD, âge du mot de passe krbtgt, statut NTLMv1)
  9. **Informations Système** (Derniers correctifs KB installés, temps d'exécution)
* **Mode Sombre Automatique :** Le rapport s'adapte automatiquement au thème (clair/sombre) de votre système d'exploitation.
* **En-têtes Figés (Sticky) :** Les noms des contrôleurs de domaine et des tests restent visibles lors du défilement vertical et horizontal.

---

## 📋 Prérequis

* **Droits d'administration :** Le script doit être exécuté avec des privilèges élevés (Exécuter en tant qu'administrateur) pour exécuter des outils comme `dcdiag` ou interroger le registre à distance.
* **Module PowerShell Active Directory** installé sur la machine d'exécution.
* **Compatibilité :** Windows Server 2012 et versions ultérieures (ou Windows 10/11 avec les outils RSAT).

---

## 🚀 Exemples d'Utilisation

### 1. Générer un rapport HTML local
Exécute le diagnostic sur l'ensemble de la forêt et enregistre le rapport HTML localement :
```powershell
.\Get-ADHealth.ps1 -Report
```

### 2. Cibler un domaine ou un contrôleur spécifique
Analyser uniquement les serveurs d'un domaine ou des contrôleurs précis :
```powershell
# Analyser un domaine spécifique
.\Get-ADHealth.ps1 -DomainName "mon-domaine.local" -Report

# Analyser un contrôleur de domaine précis
.\Get-ADHealth.ps1 -Server "DC01-PARIS" -Report
```

### 3. Exporter en CSV
Générer un fichier CSV avec les métriques brutes :
```powershell
.\Get-ADHealth.ps1 -CSV
```

### 4. Envoyer le rapport par E-mail
Lancer l'analyse et envoyer le rapport HTML directement par mail (nécessite d'ajuster les paramètres SMTP dans le script) :
```powershell
.\Get-ADHealth.ps1 -Email
```

---

## 🛠️ Configuration SMTP (pour l'envoi de rapports)

Pour utiliser la fonction d'envoi par e-mail (`-Email`), modifiez les lignes suivantes dans le script [Get-ADHealth.ps1](file:///Users/johan/workspace/perso/PwSH/Get-ADHealth/Get-ADHealth.ps1) :
```powershell
$smtpsettings = @{
    To         = 'votre-email@entreprise.com'
    From       = 'adhealth@entreprise.com'
    Subject    = "$reportemailsubject - $date"
    SmtpServer = "mail.entreprise.com"
    Port       = "25"
}
```
