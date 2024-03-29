#funcion que cifra un texto con el cifrado cesar
def encrypt_cesar(texto, corrimiento):
    texto_cifrado = ""
    for caracter in texto:
        if caracter.isalpha():
            codigo = ord(caracter)
            codigo_cifrado = (codigo - ord('a') + corrimiento) % 26 + ord('a')
            caracter_cifrado = chr(codigo_cifrado)
            texto_cifrado += caracter_cifrado
        else:
            texto_cifrado += caracter
    return texto_cifrado

input = input()
texto = input.split('"')[1] 
corrimiento = int(input.split()[-1])

texto_cifrado = encrypt_cesar(texto, corrimiento)
print(texto_cifrado)