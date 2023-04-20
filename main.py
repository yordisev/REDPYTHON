import csv
import socket
import platform
from scapy.all import *


def read_client_pc_name(ip_cliente: str):
    try:
        pc_name = socket.gethostbyaddr(ip_cliente)[0]
        
    except socket.herror:
        pc_name = "Nombre del PC no encontrado"
    return  pc_name

# Dirección IP de la red local
ip_address = "192.168.5.1/24"

# Enviar paquetes ARP para obtener información de cada equipo en la red
answered, unanswered = arping(ip_address)

# Abrir archivo CSV para escritura
with open("equipos.csv", "w", newline="") as csvfile:
    # Crear objeto para escribir en el archivo CSV
    writer = csv.writer(csvfile)

    # Escribir encabezado del archivo CSV
    writer.writerow(["Hostname","Hostname", "IP address", "MAC address"])

    # Iterar sobre los paquetes ARP respondidos
    for packet in answered:
        # Obtener dirección MAC, dirección IP y nombre del equipo
        mac_address = packet[1].hwsrc
        ip_address = packet[1].psrc
        hostname = packet[1].sprintf("%ARP.psrc%")
        informacion_equipo = read_client_pc_name(ip_address)
        print(informacion_equipo)
        # Escribir información del equipo en el archivo CSV
        writer.writerow([informacion_equipo,hostname, ip_address, mac_address])
