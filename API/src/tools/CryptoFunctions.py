import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes


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

def encryptAES(text, k):
    """ Receive a key and a text and encrypt it on AES\n
        @param k - key to make the encrypt\n
        @paran text - text that will be encrypted\n
        @return enc64 - text encrypted
    """
    cypher = AES.new(k, AES.MODE_CBC, iv)
    textPadded = pad(text)
    cy = cypher.encrypt(textPadded)
    enc64 = base64.b64encode(cy)
    return enc64

def decryptAES(text, k):
    """ Receive a key and a text and decrypt the text with the key using AES \n
        @param k - key to make te decrypt\n
        @param text - text encrypted\n
        @return plainTextUnpadded - text decrypted
    """
    enc = base64.b64decode(text)
    decryption_suite = AES.new(k, AES.MODE_CBC, iv)
    plain_text = decryption_suite.decrypt(enc)
    plainTextUnpadded = unpad(plain_text)
    return plainTextUnpadded

## RSA

#implementado
def encryptRSA2(key, plaintext):
    """ Receive a key and a text and encrypt it on Base 64\n
        @param key - key to make the encrypt\n
        @paran text - text that will be encrypted\n
        @return ciphertext64 - text encrypted in base64
    """    
    #load key
    pubkey = serialization.load_pem_public_key(
        key
    )
    
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
    
    return ciphertext64

#implementado
def decryptRSA2(key, ciphertext,password=None):
    """ Receive a key and a text and decrypt the text with the key using Base 64 \n
        @param key - key to make te decrypt\n
        @param text - text encrypted\n
        @return data - text decrypted
    """    
    #load key
    privkey = serialization.load_pem_private_key(
        key,
        password
    )
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
        return plaintext    
    except:
        return ""

#implementado
def signInfo(gwPvtKey, data,password=None):
    """ Sign some data with the peer's private key\n 
        @param gwPvtKey - peer's private key\n
        @param data - data to sign\n
        @return sinature - signature of the data maked with the private key
    """
    try:
        #load key
        privkey = serialization.load_pem_private_key(
            gwPvtKey,
            password
        )
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
        #encode the signature in b64
        signature = base64.b64encode(sig)
        return signature
    except:
        return ""

#implementado
def signVerify(data, signature, gwPubKey):
    """ Verify if a data sign by a private key it's unaltered\n
        @param data - data to be verified\n
        @param signature - signature of the data to be validated\n
        @param gwPubKey - peer's private key
    """
    try:
        #load key
        pubkey = serialization.load_pem_public_key(
            gwPubKey
        )
        
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

        return True
    except:
        return False

#implementado
def generateRSAKeyPair():
    """ Generate a pair of RSA keys using RSA 3072\n
        @return pub, prv - public and private key
    """
    
    keysize = 3072
    publicexpoent = 65537

    private = rsa.generate_private_key(
        publicexpoent,
        keysize
    )

    pubKey = private.public_key()
    
    prv = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub = pubKey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo    
    )
    
    return pub, prv


## ECC/ECDSA