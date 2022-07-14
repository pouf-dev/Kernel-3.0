#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import binascii
import hashlib
import json
import random
from Crypto.Util.number import long_to_bytes, bytes_to_long
import time

sbox = [225, 215, 45, 11, 70, 238, 109, 46, 159, 235, 57, 173, 90, 53, 85, 114, 245, 40, 78, 2, 71, 229, 199, 201, 58, 42, 177, 76, 210, 246, 12, 27, 26, 208, 243, 73, 92, 200, 206, 102, 217, 207, 17, 14, 147, 101, 170, 32, 10, 255, 80, 82, 24, 61, 95, 43, 124, 122, 216, 115, 205, 218, 75, 227, 239, 175, 152, 113, 74, 224, 248, 194, 97, 155, 91, 125, 249, 3, 25, 51, 103, 213, 204, 104, 63, 244, 145, 44, 160, 106, 21, 94, 222, 48, 121, 165, 171, 202, 31, 203, 29, 230, 156, 240, 168, 34, 129, 182, 234, 185, 241, 123, 33, 163, 15, 9, 0, 99, 7, 178, 49, 186, 154, 126, 148, 141, 130, 250, 67, 41, 232, 195, 52, 56, 118, 105, 22, 242, 184, 226, 64, 254, 162, 191, 66, 138, 20, 132, 72, 39, 221, 146, 161, 237, 86, 153, 166, 5, 120, 54, 81, 38, 77, 47, 19, 189, 4, 36, 128, 50, 111, 180, 1, 140, 13, 149, 172, 107, 181, 100, 169, 187, 83, 117, 192, 143, 139, 197, 190, 219, 136, 212, 251, 228, 231, 62, 179, 8, 60, 79, 84, 211, 144, 18, 188, 89, 35, 28, 158, 96, 30, 174, 151, 23, 112, 116, 87, 253, 127, 65, 133, 236, 220, 247, 252, 157, 55, 193, 209, 137, 196, 164, 233, 167, 16, 134, 69, 59, 98, 68, 135, 198, 223, 88, 150, 6, 142, 93, 131, 119, 108, 214, 176, 110, 183, 37]
pbox = [2, 5, 7, 4, 1, 0, 3, 6]

class Encryptor(object):
    def __init__(self, passphrase):
        self.key = hashlib.sha256(passphrase.encode()).digest()[:6]

    def generateKey(self):
        return self.key
    
    def setKey(self,k) :
    	self.key=k

    	
    def xor(self, a, b):
        res = []
        for ac, bc in zip(a, b):
            res.append(ac^bc)
        return res

    def encryptBlock(self, block):
        key = list(self.generateKey()) #renvoie une liste de 6 entiers issue du sha d'une passphrase saisie
        l = list(block[:8])#on divise le CTR en deux block de 8 bits (L  R) = CTR
        r = list(block[8:])
        for iround in range(len(key)):# pour chacun des 6 entiers dans Key
            keybyte = key.pop()
            for isubround in range(4):# on fait 4 tours avec une fonction f 
                f = []
                for i in range(8):
                    f.append(sbox[l[i] ^ keybyte])
                    keybyte = (keybyte + 1) % 256
                f = [f[pbox[i]] for i in range(8)]
                #on fait un xor de f(l) avec r qu'on met dans le block de gauche et le block de droite devient l'ancien block de gauche
                l, r = self.xor(r, f), l 
        return bytes(l+r)



    
    def decryptBlock(self,block) :
        key = list(self.generateKey())
        l = list(block[:8])
        r = list(block[8:])
        for iround in range(len(key)):
            
            for isubround in range(4):
                f = []
                keybyte = (key[iround]+(3-isubround)*8)% 256
                for i in range(8):
                    f.append(sbox[r[i] ^ keybyte])
                    keybyte = (keybyte + 1) % 256
                f = [f[pbox[i]] for i in range(8)]
                l, r = r,self.xor(l, f)
        return bytes(l+r)
        
        
	
    def encrypt(self, plaintext):
        while len(plaintext)%16:#complete avec des 0 pour avoir des block de 16 bytes
            plaintext += b'\0'

        ctr = random.getrandbits(128)#prend un nombre au hasard qu'on nomme CTR

        encrypted = ctr.to_bytes(16, 'big')#ce nombre va etre la permiere chose ecrite dans le fichier output
        for i in range(0, len(plaintext), 16):
            encryptedBlock = self.encryptBlock(ctr.to_bytes(16, 'big'))#on encrypt le CTR avec encryptBlock
            encrypted += bytes(self.xor(plaintext[i:i+16], encryptedBlock))#on fait un XOR du CTR avec le plaintext
            ctr += 1#on on ajoute 1 au CTR
        return encrypted    


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument('file', help='file path to encrypt')
    parser.add_argument('passphrase', help='Passphrase used to encrypt file')
    parser.add_argument('-O', '--output-file', help='Specify the output file')

    return parser.parse_args()


def progam():
    args = parse_args()
    print('Welcome to Encryptor')
    print('Encrypting %s using :' % args.file, args.passphrase)
    plaintext = open(args.file, 'rb').read()
    passphrase = args.passphrase
    ciphertext = Encryptor(passphrase).encrypt(plaintext)
    if args.output_file:
        print("Cipher data saved in : %s" % args.output_file)
        f = open(args.output_file, 'wb')
        f.write(ciphertext)
        f.close()
    else:
        print('Your file after encryption is', ciphertext.hex())

"""
======================================
lecture du fichier chiffré
==================================
"""
fichierChiffre="CONFIDENTIEL.xlsx.enc"# "CONFIDENTIEL.xlsx.enc"
f= open(fichierChiffre,"rb")
cypher=f.read()
f.close()

offset=0

ctr=bytes_to_long(cypher[:16])
ctr+=offset
ctr=long_to_bytes(ctr)
cypher=cypher[16:]
cypher=cypher[:16]



"""
==============================
brute force
==============================
"""
print("--------debut du brut-Force---------")

pt=b'\x50\x4B\x03\x04\x14\x00\x06\x00\x08\x00\x00\x00\x21\x00\xD5\x2D'#entete du dernier fichier XLSX
pt=Encryptor("passphrase").xor(pt,cypher) #Xor avec le XLSX.enc
cypher=b''
for i in pt :
	cypher+=i.to_bytes(1, 'big')
print("cypher = ",cypher)
e=Encryptor("passphrase")#on met n'importe quoi car on va courcircuiter la clé avec setKey voir plus bas.
encryptList=[]#liste des encryptBlock brute forcé
decryptList=[]#liste des decryptBlock brute forcé
mem=-1
start=time.time()

for k in range(256**3) :# on retrouve nos 256**3 possibilités :)
        # le k est un entier qui s'écrit XX YY ZZ en hexa
	s="{0:06x}".format(k)
	# on convertit en int chaque couple hexa [ XXb16, YYb16, ZZb16] 
	key=[int(s[i:i+2],16) for i in range(0,6,2)]   

	#########################################################
	#petit compteur qui va aller de 1 à 256 pour suivre où on en est 
	if key[0]!=mem :
		mem+=1
		print(mem,"-",int(time.time()-start)," s")
	#########################################################
		
	e.setKey(key)#fonction implémentée directement dans la classe Encrypror def setKey(self,k) : self.key=k
	encryptList.append(e.encryptBlock(ctr)) #on stoque nos valeurs
	decryptList.append(e.decryptBlock(cypher)) #on stoque nos valeurs



"""
==============================
recherche du MITM
==============================
"""
print("--------debut du MITM---------",int(time.time()-start))
l=set(encryptList) & set(decryptList)#trouve les valeurs communes
print(l)
"""
==============================
calcul de la clé
==============================
"""
kcyph=next(iter(l)) #permet de récupérer le premier element d'un ensemble {a} ==> a
#concaténation des deux clés de 3 bytes en une de 6 bytes
cletrouvee="{0:06x}".format(decryptList.index(kcyph))+"{0:06x}".format(encryptList.index(kcyph))
print("cletrouve=",cletrouvee)
key=[int(cletrouvee[i:i+2],16) for i in range(0,len(cletrouvee),2)]
print("key=",key)
print(b''.join(i.to_bytes(1, 'big') for i in key))

"""
==============================
decryptage
==============================
"""


f= open(fichierChiffre,"rb")
cypher=f.read()
f.close()
ctr=bytes_to_long(cypher[:16])
plaintext=cypher[16:]

encrypted=b''
for i in range(0, len(plaintext), 16):
    e.setKey(key)
    encryptedBlock = e.encryptBlock(ctr.to_bytes(16, 'big'))
    encrypted += bytes(e.xor(plaintext[i:i+16], encryptedBlock))
    ctr += 1
    key=list(hashlib.sha256(b''.join(i.to_bytes(1, 'big') for i in key)).digest()[:6])
f=open("victoire.xlsx","wb")
f.write(encrypted)
f.close
print("--------THE END---------",int(time.time()-start))
