import socket
import threading
from queue import Queue
import requests

# API pour vérifier les vulnérabilités (exemple : Shodan, utilisez votre propre clé API)
SHODAN_API_URL = "https://api.shodan.io/shodan/host/{ip}?key={api_key}"
SHODAN_API_KEY = "YOUR_SHODAN_API_KEY"  # Remplacez par votre clé API Shodan

# File d'attente pour les threads
queue = Queue()
# Liste pour stocker les résultats
scan_results = []

# Fonction pour scanner les ports
def port_scan(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((target, port))
    except:
        return False
    else:
        return True

# Fonction pour gérer les threads
def threader(target):
    while True:
        worker = queue.get()
        if port_scan(target, worker):
            print(f"Port {worker} est ouvert!")
            scan_results.append(worker)
        queue.task_done()

# Vérifier les vulnérabilités via l'API Shodan
def check_vulnerabilities(ip):
    url = SHODAN_API_URL.format(ip=ip, api_key=SHODAN_API_KEY)
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        return None

# Fonction principale
def main():
    target = input("Entrez l'adresse IP à scanner : ")

    # Choisissez la plage de ports
    port_range = input("Entrez la plage de ports à scanner (par ex. 1-1024) : ")
    port_start, port_end = map(int, port_range.split('-'))

    # Créer et démarrer les threads
    for x in range(100):
        t = threading.Thread(target=threader, args=(target,))
        t.daemon = True
        t.start()

    # Ajouter les tâches à la file d'attente
    for worker in range(port_start, port_end + 1):
        queue.put(worker)

    # Attendre que toutes les tâches soient terminées
    queue.join()

    print("Scan terminé!")
    print("Ports ouverts : ", scan_results)

    # Vérifier les vulnérabilités sur l'IP cible
    vulnerabilities = check_vulnerabilities(target)
    if vulnerabilities:
        print("Vulnérabilités trouvées :")
        for item in vulnerabilities.get('vulns', []):
            print(f"- {item}: {vulnerabilities['vulns'][item]['summary']}")
    else:
        print("Aucune vulnérabilité trouvée ou échec de la requête API.")

if __name__ == "__main__":
    main()
