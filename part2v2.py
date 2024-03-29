import time
from scapy.all import ICMP, IP, Raw, sr1

#Correr con sudo python3 part2-scapysend.py :)

#Dirección IP de destino
IP_dst = "127.0.0.1"
IP_src = "192.168.100.12"

def generate_icmp_packet(char, seq):
    #En esta parte se crea el payload del paquete ICMP

    payload = char.encode()  #Se convierte el caracter "Cifrado" a bytes y se guarda en payload
    payload += b'\x00' * 7  #Se agregan 7 bytes nulos

    #Finalmente se añaden los bytes del 0x10 al 0x37 al payload
    for i in range(0x10, 0x38):
        payload += bytes([i])

    #Se construye el paquete ICMP
    icmp_packet = IP(src = IP_src, dst=IP_dst)/ICMP(type=8, id=1)/Raw(load=payload)

    #Se configura el campo seq
    icmp_packet[ICMP].seq = seq

    return icmp_packet

def send_icmp_packets(message):
    seq = 1
    for char in message:
        #Se genera el paquete ICMP con el caracter y la secuencia inicial
        icmp_packet = generate_icmp_packet(char, seq)

        #Se envía el paquete ICMP y se mide el tiempo de respuesta
        start_time = time.time()
        reply = sr1(icmp_packet, verbose=False, timeout=0.5)
        end_time = time.time()

        #Se imprime el resultado del envío y si se recibió respuesta, en caso contrario se imprime que excedió el tiempo
        elapsed_time = end_time - start_time
        if reply:
            print(f"Paquete {seq} y char: {char} enviado en {elapsed_time:.3f} segundos. Respuesta: {reply.summary()}")
        else:
            print(f"El paquete {seq} excedió el límite de tiempo (0.5 segundos).")

        #Se incrementa la secuencia para el siguiente caracter y que tenga una secuencia lógica
        seq += 1

if __name__ == "__main__":

    #Aqui se recibe el mensaje y se splittean los caracteres
    texto = input()
    mensaje = texto.split('"')[1]
    message = list(mensaje)
    
    #Se le pasan los caracteres a la funcion send_icmp_packets para que los envie
    send_icmp_packets(message)

#"larycxpajorj h bnpdarmjm nw anmnb"
#"wplrfp zq wprpyod szwl ntdnz ulgl apccz wlwlwl"