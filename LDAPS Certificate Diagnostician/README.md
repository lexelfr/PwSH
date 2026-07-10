# LDAPS Certificate Diagnostician

Un script PowerShell simple et efficace pour inspecter et diagnostiquer les certificats SSL/TLS sur les serveurs LDAPS (Active Directory Domain Controllers) depuis un poste Windows, sans dépendance externe (pas besoin d'OpenSSL).

## Fonctionnalités
- Test de la connectivité TCP sur le port LDAPS.
- Vérification de la chaîne de confiance (statut de validation du certificat).
- Extraction du **Thumbprint** (Empreinte numérique).
- Extraction des **SAN (Subject Alternative Names)**, compatible avec les OS Windows FR et EN.


