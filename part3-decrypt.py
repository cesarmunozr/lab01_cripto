import scapy.all as scapy

#funcion que cifra un texto con el cifrado cesar
def encrypt_cesar(message, shift):
    texto_cifrado = ""
    for caracter in message:
        if caracter.isalpha():
            codigo = ord(caracter)
            codigo_cifrado = (codigo - ord('a') + shift) % 26 + ord('a')
            caracter_cifrado = chr(codigo_cifrado)
            texto_cifrado += caracter_cifrado
        else:
            texto_cifrado += caracter
    return texto_cifrado

#Función para descifrar el mensaje utilizando todas las combinaciones posibles de César
def decrypt_cesar(message):
    possible_decryptions = []
    for shift in range(26):
        decrypted_message = encrypt_cesar(message, -shift)
        possible_decryptions.append(decrypted_message)
    return possible_decryptions

#Función para imprimir las combinaciones de descifrado, resaltando la más probable
def print_decryptions(decryptions, most_probable_index):
    for i, decryption in enumerate(decryptions):
        if i == most_probable_index:
            print("\033[92m" + f"Key: {i}, Decryption: {decryption}" + "\033[0m")
        else:
            print(f"Key: {i}, Decryption: {decryption}")

def main():

    IP_dst = "8.8.8.8" #Este programa funciona en buscar los paquetes icmp con destino a esta IP

    #Se pide por pantalla la ruta del archivo pcapng
    pcapng_file = input("Ingrese la ruta del archivo .pcapng: ")

    #Lee el archivo pcapng y extrae el primer byte de los paquetes con destino a la IP especificada
    data = ""
    for packet in scapy.rdpcap(pcapng_file):
        if packet.haslayer(scapy.IP) and packet[scapy.IP].dst == IP_dst:
            if packet.haslayer(scapy.Raw) and len(packet[scapy.Raw].load) > 0:
                data += chr(packet[scapy.Raw].load[0])

    print("Mensaje cifrado:", data)

    #Obtiene todas las combinaciones posibles de descifrado, se guardan en una lista
    possible_decryptions = decrypt_cesar(data)

    #Diccionario de palabras en español 
    spanish_words = {...}

    #Evalua y selecciona la combinación de descifrado más probable respecto a la cantidad de mach con palabras en español del diccionario anterior
    most_probable_index = 0
    max_spanish_words = 0
    for i, decryption in enumerate(possible_decryptions):
        words = decryption.split()
        spanish_word_count = sum(word in spanish_words for word in words)
        if spanish_word_count > max_spanish_words:
            most_probable_index = i
            max_spanish_words = spanish_word_count

    #Imprime todas las combinaciones de descifrado, resaltando la más probable
    print("\nPosibles descifrados:")
    print_decryptions(possible_decryptions, most_probable_index)

if __name__ == "__main__":
    main()
