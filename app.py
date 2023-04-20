from scapy.all import *

# Dirección IP de la red local
ip_address = "192.168.52.1/24"

# Enviar paquetes ARP para obtener información de cada equipo en la red
answered, unanswered = arping(ip_address)

# Iterar sobre los paquetes ARP respondidos
for packet in answered:
    # Obtener dirección MAC, dirección IP y nombre del equipo
    mac_address = packet[1].hwsrc
    ip_address = packet[1].psrc
    hostname = packet[1].sprintf("%ARP.psrc%")

    # Imprimir información del equipo
    print(f"Equipo: {hostname} ({ip_address})")
    print(f"Dirección MAC: {mac_address}\n")
