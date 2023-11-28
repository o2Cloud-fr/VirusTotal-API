# Assurez-vous d'avoir une clé API valide de VirusTotal
$apiKey = "CléAPI"

# Chemin du fichier à analyser
$fichierPath = "C:\Chemin\vers\votre\fichier.exe"

# Obtenir le hash du fichier
$fileHash = (Get-FileHash -Path $fichierPath -Algorithm SHA256).Hash

# Construire l'URL de l'API VirusTotal
$url = "https://www.virustotal.com/vtapi/v2/file/report?apikey=$apiKey&resource=$fileHash"

# Envoyer la requête à VirusTotal
$response = Invoke-RestMethod -Uri $url -Method Get

# Vérifier la réponse
if ($response.response_code -eq 1) {
    # Analyse réussie
    Write-Host "Rapport d'analyse VirusTotal:"
    Write-Host "Scan ID: $($response.scan_id)"
    Write-Host "Nombre de scanners détectant des menaces: $($response.positives) sur $($response.total)"

    # Afficher les résultats des scanners individuels si nécessaire
    if ($response.positives -gt 0) {
        Write-Host "Résultats des scanners individuels:"
        foreach ($scanResult in $response.scans.GetEnumerator()) {
            $scanner = $scanResult.Key
            $result = $scanResult.Value.result

            # Afficher en rouge si le scanner a détecté une menace
            if ($result -ne "clean") {
                Write-Host -ForegroundColor Red "$scanner : $result"
            } else {
                Write-Host "$scanner : $result"
            }
        }
    }
} else {
    # Erreur lors de l'analyse
    Write-Host "Erreur d'analyse VirusTotal. Code de réponse: $($response.response_code)"
}