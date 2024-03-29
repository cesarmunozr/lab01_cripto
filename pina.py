import time

# Definir variables globales para la dirección IP de origen y destino
IP_SRC = "192.168.1.86"
IP_DST = "127.0.0.1"

def generate_icmp_packet(char, seq):
    # Crear el payload del paquete ICMP
    payload = char.encode()  # Convertir el carácter cifrado en bytes y colocarlo al inicio del payload

    for i in range(7):
        payload += b'\x00'  # Añadir bytes nulos al final del payload si es necesario

    # Bytes de patrón: 0x10 a 0x37
    for i in range(0x10, 0x38):
        payload += bytes([i])

    # Imprimir el payload para verificar y sequencia
    print(f"Payload para el paquete {seq}: {payload.hex()}") 
        
    

def send_icmp_packets(message):
    seq = 1
    for char in message:
        # Generar el paquete ICMP para el caracter actual
        generate_icmp_packet(char, seq)

        # Incrementar la secuencia para el próximo paquete
        seq += 1

if __name__ == "__main__":
    # Mensaje a enviar (string cifrado)
    texto = input()
    mensaje = texto.split('"')[1]
    message = list(mensaje)
    
    # Enviar los paquetes ICMP simulados
    send_icmp_packets(message)

    #"larycxpajorj h bnpdramjm nw anmnb"
    