from Crypto.Hash import SHAKE128
from Crypto.Hash import SHA3_256
import secrets
from Crypto.Cipher import AES,PKCS1_OAEP  # AES 128bits (16 Bytes)
from Crypto.PublicKey import RSA
import time as t

# Clave con sal
entrada = input("Ingrese la clave:  ")
iteraciones = int(input("Numero de iteraciones: "))
t1 = t.time()
totalTime = t.time()
salt = secrets.token_urlsafe(16)
clave = entrada + salt

#iteraciones
for i in range(iteraciones):
    h_obj = SHA3_256.new()
    h_obj.update((str.encode(clave)))
    shake = SHAKE128.new()
    shake.update(str.encode(h_obj.hexdigest())) 
    clave = str(shake.read(16).hex())
    print(clave)

key = str.encode(clave)
t2 = t.time() - t1
print('\n\nTiempo de generacion de clave HASH: ', round(t2,3), 's', 'con ', iteraciones, ' iteraciones\n')
#Encriptacion AES
t1 = t.time()
plain_text = open("example1.txt", "r", encoding='utf-8').read()
plain_text_Bytes = str.encode(plain_text)
print('\n Mensaje Codificado en Bytes: \n')
print(str.encode(plain_text))
print('\n\n')
encript_cipher = AES.new(key, AES.MODE_EAX)
nonce = encript_cipher.nonce
ciphertext, tag = encript_cipher.encrypt_and_digest(plain_text_Bytes)
#last_key = cipher.iv # IMPORTANTE!!!!
t2 = t.time() - t1
print('Tiempo de Encriptacion AES: ', round(t2,3), 's\n')

#encriptacion RSA clave privada
t1 = t.time()
keyRSA = RSA.generate(2048)
t2 = t.time() - t1
print('Tiempo de Generacion de llaves RSA: ', round(t2,3), 's\n')
private_key = keyRSA.export_key()
file_out = open("private.pem", "wb")
file_out.write(private_key)
file_out.close()

#Encriptacion RSA clave Publica
t1 = t.time()
public_key = keyRSA.publickey().export_key()
file_out = open("receiver.pem", "wb")
file_out.write(public_key)
file_out.close()


#Encriptacion de key AES con RSA
file_out = open("encripted_key.bin", "wb")
recipient_key = RSA.import_key(open("receiver.pem").read())
cipher_rsa = PKCS1_OAEP.new(recipient_key)
enc_session_key = cipher_rsa.encrypt(key)


#Guardar Datos encriptados en archivo .bin
[ file_out.write(x) for x in (enc_session_key, encript_cipher.nonce, tag, ciphertext) ]
file_out.close()


#Desencriptar!
file_in = open("encripted_key.bin", "rb")
private_key = RSA.import_key(open("private.pem").read())
enc_session_key, nonce, tag, ciphertext = \
    [ file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]

#Desencriptar key de AES con llave privada RSA
cipher_rsa = PKCS1_OAEP.new(private_key)
session_key = cipher_rsa.decrypt(enc_session_key)

#Desencriptar AES, comrpobar y mostrar
cipher = AES.new(session_key, AES.MODE_EAX, nonce=nonce)
plaintext = cipher.decrypt(ciphertext)
try:
    cipher.verify(tag)
    print("El mensaje es autentico: \n", plaintext)
except ValueError:
    print("Llave incorrecta o mensaje corrupto")

t2 = t.time() - t1
print('\nTiempo de Encriptacion y desencriptacion: ', round(t2,3), 's\n')

totalTimefin = t.time() - totalTime
print('Tiempo total de ejecucion: ', round(totalTimefin,3), 's')