import base64
import hashlib
# from Crypto.Cipher import AES
# from Crypto.Hash import SHA256
# from Crypto.PublicKey import RSA
# from Crypto.Signature import PKCS1_v1_5

from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
#from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


iv = "4242424242424242"
BS = 32
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s: s[0:-ord(s[-1])]

def calculateHash(index, previousHash, timestamp, nonce, key, blockContext, device):
    """ Calculate the hash of all arguments concatenated in the order as declared\n
        @param index - block index\n
        @param previousHash - previous block hash\n
        @param timestamp - generation time of the block\n
        @param nonce - nonce of the block\n
        @param key - key of the block\n
        @param blockContext - blockContext of the block\n
        @param device - device name of the block\n
        @return val - hash of it all
    """
    shaFunc = hashlib.sha256()
    shaFunc.update((str(index) + str(previousHash) + str(timestamp) + str(nonce) + str(
        key) + str(blockContext) + str(device)).encode('utf-8'))
    val = shaFunc.hexdigest()
    return val

def calculateHashForBlock(block):
    """ Receive a block and calulates his hash using the index, previous block hash, timestamp and the public key of the block\n
        @return result of calculateHash function - a hash
    """
    return calculateHash(block.index, block.previousHash, block.timestamp, block.nonce, 
                         block.publicKey, block.blockContext, block.device)

def calculateTransactionHash(blockLedger):
    """ Receive a transaction and calculate the hash\n
        @param blockLedger - transaction object\n
        @return hash of (index + previousHash + timestamp + data + signature) UTF-8
    """
    shaFunc = hashlib.sha256()
    shaFunc.update((str(blockLedger.index) + str(blockLedger.previousHash) + str(blockLedger.timestamp) + str(
        blockLedger.data) + str(blockLedger.signature)+ str(blockLedger.nonce)+ str(blockLedger.identification)).encode('utf-8'))
    val = shaFunc.hexdigest()
    return val

#implementado
def encryptAES(text, k):
    """ Receive a key and a text and encrypt it on AES\n
        @param k - key to make the encrypt\n
        @paran text - text that will be encrypted\n
        @return enc64 - text encrypted
    """
    # instancia o algoritmo de Cifra
    cypher = Cipher(algorithms.AES(k),modes.CBC(iv)).encryptor()
    # instancia o padder e faz o padding
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    textPadded = padder.update(text)
    textPadded += padder.finalize()
    #cifra
    cy = cypher.update(textPadded)
    cy += cypher.finalize()
    #encoda em b64
    enc64 = base64.b64encode(cy)
    return enc64

#implementado
def decryptAES(text, k):
    """ Receive a key and a text and decrypt the text with the key using AES \n
        @param k - key to make te decrypt\n
        @param text - text encrypted\n
        @return plainTextUnpadded - text decrypted
    """
    #decoda o texto em b64
    enc = base64.b64decode(text)
    # instancia o algoritmo de Cifra
    decypher = Cipher(algorithms.AES(k),modes.CBC(iv)).decryptor()
    
    #decifra
    plain_text = decypher.update(enc)
    plain_text += decypher.finalize()
    
    # instancia o unpadder e faz o unpadding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plainTextUnpadded = unpadder.update(plain_text)
    plainTextUnpadded += unpadder.finalize()
    
    return plainTextUnpadded

## RSA

#implementado
def encryptRSA2(key, plaintext):
    """ Receive a key and a text and encrypt it on Base 64\n
        @param key - key to make the encrypt\n
        @paran text - text that will be encrypted\n
        @return ciphertext64 - text encrypted in base64
    """    
    try:
        print("\tentrou no encryptRSA!!")
        # print("key: \n{}size: {}".format(key,len(key)))
        
        # bytesa = bytearray(key,'utf-8')
        
        # print("bytes: \n{}testeCARALHO".format(bytesa))
        # print(bytesa)
                
        # f=open("testekey.txt","r")
        # chave = f.read()
        
        # key = key.rstrip('\n')
        # print("key: {}abdkasbdsakjdnajs".format(key))
        # if isinstance(key,str):
        key = key.encode('utf-8')
        
        # print("comparacao de tamanhos:")
        # print("chave - {} # key - {}".format(len(chave),len(key)))

        #load key
        pubkey = serialization.load_pem_public_key(
            key
        )
        
        print("\tcarregou a chave com sucesso!!")
        #encrypt the text
        ciphertext = pubkey.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        #encode the ciphertext in b64
        ciphertext64 = base64.b64encode(ciphertext)
        
        # print("saiu do encryptRSA com chave: \n{}".format(ciphertext64))
        print("\tsaiu do encryptRSA!!")
    except Exception as e:
        print("erro: {}".format(e))
    return ciphertext64

#implementado
def decryptRSA2(key, ciphertext,password=None):
    """ Receive a key and a text and decrypt the text with the key using Base 64 \n
        @param key - key to make te decrypt\n
        @param text - text encrypted\n
        @return data - text decrypted
    """    
    print("entrou no decrypt")
    #load key
    privkey = serialization.load_pem_private_key(
        key,
        password
    )
    print("carregou a chave sem erro")
    #decifra
    try:
        plaintext = privkey.decrypt(
            #decode the b64 ciphertext
            base64.b64decode(ciphertext),
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print("saiu do decrypt sem erro")
        return plaintext    
    except:
        print("saiu do decrypt com erro")
        return ""

#implementado
def signInfo(gwPvtKey, data,password=None):
    """ Sign some data with the peer's private key\n 
        @param gwPvtKey - peer's private key\n
        @param data - data to sign\n
        @return sinature - signature of the data maked with the private key
    """
    try:
        print("\tantes de carregar a chave de assinatura!!")
        #load key
        privkey = serialization.load_pem_private_key(
            gwPvtKey,
            password
        )
        print("\tchave carregada com sucesso!!")
        #sign the data
        #TODO prehashed
        sig = privkey.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("\tassinado com sucesso!!")
        #encode the signature in b64
        signature = base64.b64encode(sig)
        # print("assinatura em b64: {}".format(signature))
        return signature
    except Exception as e:
        print("erro: {}".format(e))
        return ""

#implementado
def signVerify(data, signature, gwPubKey):
    """ Verify if a data sign by a private key it's unaltered\n
        @param data - data to be verified\n
        @param signature - signature of the data to be validated\n
        @param gwPubKey - peer's private key
    """
    try:
        print("\tantes de carregar a chave de verificacao!!")
        #load key
        pubkey = serialization.load_pem_public_key(
            gwPubKey
        )
        print("\tchave carregada com sucesso!!")
        #verify the signature
        #TODO prehashed
        pubkey.verify(
            #decode the b64 signature
            base64.b64decode(signature),
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("\tassinatura valida!!")
        return True
    except Exception as e:
        print("erro: {}".format(e))
        return False

#implementado
def generateRSAKeyPair():
    """ Generate a pair of RSA keys using RSA 3072\n
        @return pub, prv - public and private key
    """
    #print("entrou no generate RSA keys")
    keysize = 3072
    publicexpoent = 65537

    private = rsa.generate_private_key(
        publicexpoent,
        key_size=keysize
    )
    #print("gerou a chave privada")

    pubKey = private.public_key()

    #print("gerou a chave publica")
    
    prv = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    # print("serializou a chave privada: \n{}\nsize: {}".format(prv,len(prv)))
    pub = pubKey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo    
    )
    # print("serializou a chave publica: \n{}\nsize: {}".format(pub,len(pub)))
    
    #print("saiu do generate RSA keys")
    return pub, prv


## ECC/ECDSA

def signInfoECDSA(gwPvtKey, data,password=None):
    """ Sign some data with the peer's private key\n 
        @param gwPvtKey - peer's private key\n
        @param data - data to sign\n
        @return sinature - signature of the data maked with the private key
    """
    #load key
    privatekey = ec.generate_private_key()
    """  = serialization.load_pem_private_key(
        gwPvtKey,
        password
    ) """
    #assina
    sign = privatekey.sign(
        data,
        ec.ECDSA(hashes.SHA256())
    )
    
    print("gwPvtKey: {} \ndata: {} \npassword: {}".format(gwPvtKey,data,password))

def signVerifyECDSA(data, signature, gwPubKey):
    """ Verify if a data sign by a private key it's unaltered\n
        @param data - data to be verified\n
        @param signature - signature of the data to be validated\n
        @param gwPubKey - peer's private key
    """
    print("data: {} \nsignature: {} \ngwPubKey: {}".format(data,signature,gwPubKey))

def generateECDSAKeyPair():
    """ Generate a pair of ECDSA keys using SECP256R1\n
        @return pub, prv - public and private key
    """
    privatekey = ec.generate_private_key(
        ec.SECP256R1
    )
    publickey = privatekey.public_key()
    
    prv = privatekey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub = publickey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return pub, prv



