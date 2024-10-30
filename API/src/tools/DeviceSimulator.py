#import __builtin__

import sys
import os
import time
import socket
import random
import pickle
import base64
from datetime import datetime

import Pyro4

import json
import requests
import traceback
import threading

# from Crypto.PublicKey import RSA

# SpeedCHAIN modules
import Logger as Logger
import CryptoFunctions

logger = Logger.logging.getLogger("speedychain")
deviceName = ""
consensus = "None"
fname = socket.gethostname()

server = "localhost"
serverAESEncKey = ""
serverAESKey = ""
privateKey = ""
publicKey = ""
keysArray =[] # structure to save private, public, and aes key from a device
trInterval = 10000 # interval between transactions

logT27 = []
logT27.append("test;T27")
logT30 = []
logT31 = []
startTime=0
endTime=0
# input = getattr(__builtin__, 'raw_input', input)

lifecycleMethods = []
lifecycleTypes = []
lifecycleDeviceName = ""
lifecycleMultiMode = "lifecycleMulti"

logCreateSignTime = []
logVerifySignTime = []
logCreateTransactTime = []
logSignSize = []
logTransactSize = []
logXTransactSize = []
signatureAlgoritm = "RSA"

def getMyIP():
     """ Return the IP from the gateway
     @return str 
     """
     # s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
     # s.connect(("8.8.8.8", 80))
     # myIP = s.getsockname()[0]
     # s.close()
     # hostname = socket.gethostname()
     # IPAddr = socket.gethostbyname(hostname)
     # myIP = IPAddr

     try:
         s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
         s.connect(("10.255.255.255", 1))
         myIP = s.getsockname()[0]
     except:
         myIP = '127.0.0.1'
     finally:
         s.close()
     return myIP


def setServer():
    """ Ask for the user to input the server URI and put it in the global var 'server' """
    #server = raw_input('Gateway IP:')
    uri = str(input("Enter the uri of the gateway: ")).strip()
    setServerWithUri(uri)

def setServerWithUri(uri):
    global server    
    global lifecycleDeviceName
    server = Pyro4.Proxy(uri) 
    lifecycleDeviceName = server.getDeviceName()
    # print("Lifecycle name: " + str(lifecycleDeviceName))

def addBlockOnChain():
    """ Take the value of 'publicKey' var, and add it to the chain as a block"""
    global serverAESEncKey
    # print("###addBlockonChain in devicesimulator, publicKey")
    # print(publicKey)
    # print("antes de chamar o server")
    serverAESEncKey = server.addBlock(publicKey, lifecycleDeviceName)
    if serverAESEncKey == "":
        # print("entrou no if")
        print("Block already added with this public key")
        logger.error("it was not possible to add block - problem in the key")
        return False
    else:
        # print("entrou no else")
        # print("###addBlockonChain in devicesimulator, serverAESEncKey")
        # print(serverAESEncKey)
        # while len(serverAESEncKey) < 10:
        #    serverAESEncKey = server.addBlock(publicKey)
        decryptAESKey(serverAESEncKey)
        # print("###after decrypt aes")
    return True
    # print("###after decrypt aes")

def addBlockOnChainv2(devPubKey, devPrivKey):
    """ Take the value of 'publicKey' var, and add it to the chain as a block"""
    # print("###addBlockonChain in devicesimulator, publicKey")
    # print(publicKey)
    # pickedDevPubKey = pickle.dumps(devPubKey)
    # print("antes de chamar o server-addblock2")
    serverAESEncKey = server.addBlock(devPubKey, lifecycleDeviceName)
    if (len(str(serverAESEncKey))<10):
        logger.error("it was not possible to add block - problem in the key")
        return False
    # print("###addBlockonChain in devicesimulator, serverAESEncKey")
    # print(serverAESEncKey)
    # while len(serverAESEncKey) < 10:
    #    serverAESEncKey = server.addBlock(publicKey)
    try:
        # print("tentativa de decifrar a chave AES-addblock2")
        AESKey = CryptoFunctions.decryptRSA2(devPrivKey, serverAESEncKey)
    except:
        logger.error("problem decrypting the AES key")
        return False
    return AESKey


def sendDataTest():
    """ Send fake data to test the system """
    global logCreateSignTime
    global logVerifySignTime
    global logSignSize
    pub, priv = CryptoFunctions.generateRSAKeyPair()
    temperature = readSensorTemperature()
    t = ((time.time() * 1000) * 1000)
    timeStr = "{:.0f}".format(t)
    data = timeStr + temperature
    t1 = time.time()
    signedData = CryptoFunctions.signInfo(priv, data)
    t2 = time.time()
    logCreateSignTime.append("SignatureCreate;"+ signatureAlgoritm + ";{0:.12f};ms".format((t2 - t1) * 1000))
    print("sign logged")
    signSize = len(signedData)
    logSignSize.append("signatureSize"+ signatureAlgoritm+";"+ str(signSize) + ";Bytes"+ ";data test" )
    print("size logged")
    ver = CryptoFunctions.signVerify(data, signedData, pub)
    t3 = time.time()
    logVerifySignTime.append("SignatureVerify;"+ signatureAlgoritm + ";{0:.12f};ms".format((t3 - t2) * 1000))
    print("sign logged")
    logger.debug("Sending data test " + str(ver) + "...")
    # print ("done: "+str(ver))

def sendData():
    """ Read the sensor data, encrypt it and send it as a transaction to be validated by the peers """
    global logCreateSignTime
    global logSignSize
    global logCreateTransactTime
    global logTransactSize
    ttransact1 = time.time()
    # logger.info("entrou no sendData")
    temperature = readSensorTemperature()
    t = ((time.time() * 1000) * 1000)
    timeStr = "{:.0f}".format(t)
    data = timeStr + temperature
    logger.debug("data = "+data)
    # logger.info("antes de assinar")
    t1 = time.time()
    signedData = CryptoFunctions.signInfo(privateKey, data)
    t2 = time.time()
    logCreateSignTime.append("SignatureCreate;"+ signatureAlgoritm + ";{0:.12f};ms".format((t2 - t1) * 1000))
    print("sign logged")
    signSize = len(signedData)
    logSignSize.append("signatureSize"+ signatureAlgoritm+";"+ str(signSize) + ";Bytes"+ ";data in transaction" )
    print("size logged")
    # logger.info("dps de assinar")
    # print("assinatura: {} ----".format(signedData))
    # if(CryptoFunctions.signVerify(data,signedData,publicKey)):
    #     print("assinado corretamente")
    # else:
    #     print("erro na assinatura")
    toSend = signedData + timeStr + temperature

    try:
        # logger.info("antes de cifrar")
        encobj = CryptoFunctions.encryptAES(toSend, serverAESKey)
        ttransact2 = time.time()
        logCreateTransactTime.append("TransactionCreate;"+signatureAlgoritm+";{0:.12f};ms".format((ttransact2 - ttransact1) * 1000))
        print("transact time logged")
        sizeTransact = len(base64.b64decode(encobj))
        logTransactSize.append("TransactionSize;"+ signatureAlgoritm +";"+str(sizeTransact)+";Bytes")
        print("transact size logged")
    except:
        logger.error("was not possible to encrypt... verify aeskey")
        newKeyPair()
        addBlockOnChain() # this will force gateway to recreate the aes key
        ttransact3 = time.time()
        t1 = time.time()
        signedData = CryptoFunctions.signInfo(privateKey, data)
        t2 = time.time()
        logCreateSignTime.append("SignatureCreate;"+ signatureAlgoritm + ";{0:.12f};ms".format((t2 - t1) * 1000))
        print("sign logged")
        signSize = len(signedData)
        logSignSize.append("signatureSize"+ signatureAlgoritm+";"+ str(signSize) + ";Bytes"+ ";data in transaction" )
        print("size logged")
        toSend = signedData + timeStr + temperature
        encobj = CryptoFunctions.encryptAES(toSend, serverAESKey)
        ttransact4 = time.time()
        logCreateTransactTime.append("TransactionCreate;"+signatureAlgoritm+";{0:.12f};ms".format((ttransact4 - ttransact3) * 1000))
        print("transact time logged")
        sizeTransact = len(base64.b64decode(encobj))
        logTransactSize.append("TransactionSize;"+ signatureAlgoritm +";"+str(sizeTransact)+";Bytes")
        print("transact size logged")
        logger.error("passed through sendData except")
    try:
        if(server.addTransaction(publicKey, encobj)=="ok!"):
            logger.error("everything good now")
            return True
        else:
            logger.error("something went wrong when sending data")
    except:
        logger.error("some exception with addTransaction now...")


def sendDataSC(stringSC):
    global logCreateSignTime
    global logSignSize
    global logCreateTransactTime
    global logTransactSize
    ttransact1 = time.time()
    t = ((time.time() * 1000) * 1000)
    timeStr = "{:.0f}".format(t)
    data = timeStr + stringSC
    t1 = time.time()
    signedData = CryptoFunctions.signInfo(privateKey, data)
    t2 = time.time()
    logCreateSignTime.append("SignatureCreate;"+ signatureAlgoritm + ";{0:.12f};ms".format((t2 - t1) * 1000))
    print("sign logged")
    signSize = len(signedData)
    logSignSize.append("signatureSize"+ signatureAlgoritm+";"+ str(signSize) + ";Bytes"+ ";data in transactionSC")
    print("size logged")
    logger.debug("###Printing Signing Data before sending: "+signedData)
    # print ("###Signature lenght: " + str(len(signedData)))
    toSend = signedData + timeStr + stringSC
    encobj = CryptoFunctions.encryptAES(toSend, serverAESKey)
    ttransact2 = time.time()
    logCreateTransactTime.append("TransactionCreate;"+signatureAlgoritm+";{0:.12f};ms".format((ttransact2 - ttransact1) * 1000))
    print("transact time logged")
    sizeTransact = len(base64.b64decode(encobj))
    logTransactSize.append("TransactionSize;"+ signatureAlgoritm +";"+str(sizeTransact)+";Bytes")
    print("transact size logged")
    server.addTransactionSC(publicKey, encobj)
    # server.addTransaction(toSend)

def decryptAESKey(data):
    """ Receive a encrypted data, decrypt it and put it in the global var 'serverAESKey' """
    global serverAESKey
    try:
        serverAESKey = CryptoFunctions.decryptRSA2(privateKey, data)
    except:
        logger.error("problem decrypting the AES key")

def readSensorTemperature():
    """ Generates random data like '23 C' """
    temp = str(random.randint(10, 40)) + " C"
    return temp

def addPeer():
    """ Ask for the user to inform a peer URI and add it to the server """
    # if sys.version_info < (3, 0):
    #     input = raw_input
    uri = input("Enter the PEER uri: ").strip()
    server.addPeer(uri, True)

def listBlockHeader():
    """ Log all blocks """
    server.showIoTLedger()

def listTransactions():
    """ Ask for the user to input an index and show all transaction of the block with that index """
    index = input("Which IoT Block do you want to print?")
    server.showBlockLedger(int(index))


def listPeers():
    """ List all peers in the network """
    logger.debug("calling server...")
    server.listPeer()

def newKeyPair():
    """ Generates a new pair of keys and put is on global vars 'privateKey' and 'publicKey' """
    global privateKey
    global publicKey
    publicKey, privateKey = CryptoFunctions.generateRSAKeyPair()
    while len(publicKey) < 10 or len(privateKey) < 10:
        publicKey, privateKey = CryptoFunctions.generateRSAKeyPair()


def brutePairAuth(retry):
    """ Add a block on the chain with brute force until it's add"""
    isOk = True
    while isOk:
        try:
            newKeyPair()
            addBlockOnChain()
            isOk = False
        except KeyboardInterrupt:
            sys.exit()
        except:
            logger.error("failed to execute pairauth:"+str(retry))
            isOk = True

def bruteSend(retry):
    """ Try to send a random data with brute force until it's sended """
    isOk = True
    while isOk:
        try:
            sendData()
            isOk = False
        except KeyboardInterrupt:
            sys.exit()
        except:
            logger.error("failed to execute send tr:"+str(retry))
            exc_type, exc_value, exc_traceback = sys.exc_info()
            logger.error("*** print_exception:\n" + str(traceback.print_exception(exc_type, exc_value, exc_traceback, limit=2, file=sys.stdout)))
            #global serverAESKey
            # print("the size of the serverAESKey is: "+str(len(serverAESKey)))
            # time.sleep(0.001)
            return False # addBlockConsensusCandiate

def multSend(devPubK, devPrivateK, AESKey, retry, blk):
    # print("\tentrou no multsend!!!")
    try:
        # print("tentando sendDataArgs")    
        return sendDataArgs(devPubK, devPrivateK, AESKey, retry, blk)
    except KeyboardInterrupt:
        sys.exit()
    except:
        logger.error("failed to execute send tr:" + str(retry)+"from Blk: "+ str(blk))
        exc_type, exc_value, exc_traceback = sys.exc_info()
        logger.error("*** print_exception:\n" + str(
            traceback.print_exception(exc_type, exc_value, exc_traceback, limit=2, file=sys.stdout)))
        # global serverAESKey
        # print("the size of the serverAESKey is: "+str(len(serverAESKey)))
        # time.sleep(0.001)
        return False  # addBlockConsensusCandiate

def sendDataArgs(devPubK, devPrivateK, AESKey, trans, blk):
    """ Read the sensor data, encrypt it and send it as a transaction to be validated by the peers """
    global logT30
    global logT31
    global keysArray
    global logCreateSignTime
    global logSignSize
    global logCreateTransactTime
    global logTransactSize
    ttransact1 = time.time()
    temperature = readSensorTemperature()
    t = ((time.time() * 1000) * 1000)
    timeStr = "{:.0f}".format(t)
    data = timeStr + temperature
    logger.debug("data = "+data)
    t1 = time.time()
    signedData = CryptoFunctions.signInfo(devPrivateK, data)
    t2 = time.time()
    logCreateSignTime.append("SignatureCreate;"+ signatureAlgoritm + ";{0:.12f};ms".format((t2 - t1) * 1000))
    print("sign logged")
    signSize = len(signedData)
    logSignSize.append("signatureSize"+ signatureAlgoritm+";"+ str(signSize) + ";Bytes"+ ";data in transaction args" )
    print("size logged")
    # print("dados 'coletados' e assinados")
    # print("\nassinatura: {}".format(signedData))
    # print("\ntamanho assinatura: {}".format(len(signedData)))
    # print("\ntimestamp: {}".format(timeStr))
    # print("\ntamanho timestamp: {}".format(len(timeStr)))
    # print("\ntemperature: {}".format(temperature))
    # print("\ntamanho temperature: {}".format(len(temperature)))
    toSend = signedData + timeStr + temperature
    # print("objeto aberto: {}".format(toSend))

    try:
        # print("tenta cifrar os dados com AES")
        encobj = CryptoFunctions.encryptAES(toSend, AESKey)
        # print("cifrado com sucesso")
        # print("objeto cifrado: {}".format(encobj))
        ttransact2 = time.time()
        logCreateTransactTime.append("TransactionCreate;"+signatureAlgoritm+";{0:.12f};ms".format((ttransact2 - ttransact1) * 1000))
        print("transact time logged")
        sizeTransact = len(base64.b64decode(encobj))
        logTransactSize.append("TransactionSize;"+ signatureAlgoritm +";"+str(sizeTransact)+";Bytes")
        print("transact size logged")
        t2 = ((time.time() * 1000) * 1000)
        logT30.append("Device;" + deviceName + ";T30; Time to create a transaction;" + str((t2 - t) / 1000))
        # print(("Device;" + deviceName + ";T30; Time to create a transaction;" + str((t2 - t) / 1000)))

    except:
        logger.error("was not possible to encrypt... verify aeskey: "+ str(AESKey) +" in blk: " + str(blk) + "tr: " + str(trans))
        devPubK, devPrivateK = CryptoFunctions.generateRSAKeyPair()
        AESKey = addBlockOnChainv2(devPubK, devPrivateK) # this will force gateway to recreate the aes key
        # logger.error("New aeskey is: "+ str(AESKey))
        ttransact3 = time.time()
        t = ((time.time() * 1000) * 1000)
        timeStr = "{:.0f}".format(t)
        data = timeStr + temperature
        t1 = time.time()
        signedData = CryptoFunctions.signInfo(devPrivateK, data)
        t2 = time.time()
        logCreateSignTime.append("SignatureCreate;"+ signatureAlgoritm + ";{0:.12f};ms".format((t2 - t1) * 1000))
        print("sign logged")
        signSize = len(signedData)
        logSignSize.append("signatureSize"+ signatureAlgoritm+";"+ str(signSize) + ";Bytes"+ ";data in transaction" )
        print("size logged")
        toSend = signedData + timeStr + temperature
        encobj = CryptoFunctions.encryptAES(toSend, AESKey)
        ttransact4 = time.time()
        logCreateTransactTime.append("TransactionCreate;"+signatureAlgoritm+";{0:.12f};ms".format((ttransact4 - ttransact3) * 1000))
        print("transact time logged")
        sizeTransact = len(base64.b64decode(encobj))
        logTransactSize.append("TransactionSize;"+ signatureAlgoritm +";"+str(sizeTransact)+";Bytes")
        print("transact size logged")
        t2 = ((time.time() * 1000) * 1000)
        logT30.append("Device;" + deviceName + ";T30; Time to create a transaction;" + str((t2 - t) / 1000))
        # print(("Device;" + deviceName + ";T30; Time to create a transaction;" + str((t2 - t) / 1000)))
        logger.error("passed through sendData except")
    try:
        encobj=pickle.dumps(encobj)
        devPubK = pickle.dumps(devPubK)
        # print("manda transacao pra pool")
        transactionStatus= server.addTransactionToPool(devPubK, encobj)
        # print("e recebe o status")
        t3 = ((time.time() * 1000) * 1000)
        logT31.append("Device;" + deviceName + ";T31; Time to send/receive a transaction;" + str((t3 - t2) / 1000))
        # print("Device;" + deviceName + ";T31; Time to send/receive a transaction;" + str((t3 - t2) / 1000))
        if(transactionStatus=="ok!"):
            # logger.error("everything good now")
            return devPubK,devPrivateK,AESKey
        else:
            # logger.error("Used AESKey was: " + str(AESKey))
            logger.error("something went wrong when sending data in blk: " + str(blk) + " tr: " + str(trans))
            logger.error("Transaction status problem: " + transactionStatus)
            return devPubK,devPrivateK,AESKey
    except:
        logger.error("some exception with addTransaction now...in blk: " + str(blk) + " tr: " + str(trans))
        return devPubK,devPrivateK,AESKey


def defineAutomaNumbers():
    """ Ask for the user to input how many blocks and transaction he wants and calls the function automa()"""
    blocks = int(input('How many Blocks:'))
    trans = int(input('How many Transactions:'))
    automa(blocks, trans)

def defineContextsAutomaNumbers():
    """ Ask for the user to input how many context (been reviewed), blocks and transaction he wants and calls the function automa()"""
    # numContexts = int(input('How many Contexts(1 to n, default 3):'))
    blocks = int(input('How many Blocks/Devices:'))
    trans = int(input('How many Transactions:'))

    # need to be reviewed -> should change list of peeers
    # try:
    #     setContexts(numContexts)
    # except:
    #     logger.error("Probably, another interface set the numbers of contexts")

    automa(blocks, trans)

def setContexts(numContexts):
    contextsToSend = []
    for i in range(numContexts):

        contextStr = "000" + str(i + 1)
        # use same consensus as defined previously
        contextConsensus = consensus
        contextTuple = (contextStr,contextConsensus)
        contextsToSend.append(contextTuple)

    server.setContexts(contextsToSend)


def saveDeviceLog():
    global logT27
    global logT30
    global logT31

    for i in range(len(logT30)):
        logger.info(logT30[i])
    print("Log T30 saved")
    logT30 = []

    for i in range(len(logT31)):
        logger.info(logT31[i])
    print("Log T31 saved")
    logT31 = []

    for i in range(len(logT27)):
        logger.info(logT27[i])
    print("Log T27 saved")
    logT27 = []


def consensusTrans():
    # for i in range(1,100):
    #     print("Hello - I am a test message for the thread")
    #     time.sleep(1)
    while(True):
        # server.performTransactionConsensus()
        server.performTransactionPoolConsensus()
        time.sleep(0.01)


# for parallel simulation of devices and insertions use this
def simDevBlockAndTransSequential(blk, trans):
    # print("\tentrou no simDevBlockAndTransSequential")
    numTrans = trans
    # trInterval is amount of time to wait before send the next tr in ms
    global trInterval
    global startTime
    global keysArray

    if (trans == 0):
        # print("if trans == 0")
        devPubK, devPrivK = CryptoFunctions.generateRSAKeyPair()
        counter = 0
        AESKey = addBlockOnChainv2(devPubK, devPrivK)
        keysArray.append([devPubK, devPrivK, AESKey])
        while (AESKey == False):
            logger.error("ERROR: creating a new key pair and trying to create a new block")
            devPubK, devPrivK = CryptoFunctions.generateRSAKeyPair()
            AESKey = addBlockOnChainv2(devPubK, devPrivK)
            keysArray[blk]=[devPubK, devPrivK, AESKey]
            counter = counter + 1
            if (counter > 10):
                break
        if (startTime==0):
            startTime = (time.time())*1000*1000
        logger.info("Sending transaction blk #" + str(blk) + "tr #" + str(trans) + "...")
    # t1 = time.time()

    devPubK=keysArray[blk][0]
    devPrivK=keysArray[blk][1]
    AESKey=keysArray[blk][2]
    while (not (server.isBlockInTheChain(devPubK))):
        time.sleep(0.001)
        # continue
        # time.sleep(1)
    # print("pre multsend")
    devPubK, devPrivK, AESKey = multSend(devPubK, devPrivK, AESKey, trans, blk)
    # print("pos multsend")
    if (AESKey != False):
        keysArray[blk][2]=AESKey
    # t2 = time.time()
    #
    # if ((t2 - t1) * 1000 < trInterval):
    #     t2 = time.time()
    #     # trInterval is in ms and time.sleep is in s, so you should divide by 1000
    #     time.sleep((trInterval - ((t2 - t1) * 1000)) / 1000)

def simDevBlockAndTrans(blk, trans):
    numTrans=trans
    devPubK,devPrivK = CryptoFunctions.generateRSAKeyPair()
    # trInterval is amount of time to wait before send the next tr in ms
    global trInterval
    global startTime
    global keysArray


    counter = 0
    AESKey = addBlockOnChainv2(devPubK,devPrivK)
    while (AESKey == False):
        logger.error("ERROR: creating a new key pair and trying to create a new block")
        devPubK, devPrivK = CryptoFunctions.generateRSAKeyPair()
        AESKey = addBlockOnChainv2(devPubK, devPrivK)
        counter = counter + 1
        if (counter > 10):
            break
    # brutePairAuth(blk)
    # wait a little bit before sending tx
    time.sleep(90)
    for tr in range(0, numTrans):
        # logger.info("Sending transaction blk #" + str(blk) + "tr #" + str(tr) + "...")
        if (tr == 0):
            if (startTime==0):
                startTime = (time.time())*1000*1000
            logger.info("Sending transaction blk #" + str(blk) +"tr #"+ str(tr) + "...")
        if (tr == int(numTrans/2)):
            logger.info("Sending transaction blk #" + str(blk) + "tr #" + str(tr) + "...")
        # we can set time interval
        t1 = time.time()
        # sendData()
        while (not (server.isBlockInTheChain(devPubK))):
            time.sleep(0.001)
            # continue
            # time.sleep(1)
        devPubK, devPrivK, AESKey = multSend(devPubK, devPrivK, AESKey, tr, blk)
        t2=time.time()
        #
        if((t2-t1)*1000 < trInterval):
            t2=time.time()
            # trInterval is in ms and time.sleep is in s, so you should divide by 1000
            time.sleep((trInterval - ((t2-t1)*1000))/1000)


# for sequential generation of blocks and transactions (sequential devices), use this
def seqDevSim(blk,trans):
    logger.info("Adding block #" + str(blk) + "...")
    newKeyPair()
    counter = 0
    while(addBlockOnChain()==False):
        logger.error("ERROR: creating a new key pair and trying to create a new block")
        newKeyPair()
        counter= counter + 1
        if (counter > 10):
            break

    # brutePairAuth(blk)
    for tr in range(0, trans):
        logger.info("Sending transaction #" + str(tr) + "...")
        # sendData()
        while (not (server.isBlockInTheChain(publicKey))):
            time.sleep(0.0001)
            continue
            # time.sleep(1)
        bruteSend(tr)


def automa(blocks, trans, mode = "sequential"):
    """ Adds a specifc number of blocks and transaction to the chain\n
        @param blocks - int number of blocks\n
        @param trans - int number of transactions
    """
    # print("\tentrou no automa!!")
    time.sleep(5)
    if mode == lifecycleMultiMode:
        server.startTransactionsConsThreadsMulti()
    else:
        server.startTransactionsConsThreads()
    # print("iniciou as threads")
    time.sleep(5)
    global endTime
    global startTime
    global logT27

    # print("pre simulate devices")
    simulateDevices(blocks,trans,mode)
    # print("pos simulate devices")

    endTime = (time.time())*1000*1000
    logT27.append("Device;" + deviceName + ";T27; Time run all transactions in ms;" + str((endTime - startTime)/1000))
    time.sleep(90)
    print("saving Gw logs")
    try:
        gwSaveLog()
    except:
        print("another is saving the logs")
    print("Saved Gw logs, now saving Dev logs")
    saveDeviceLog()
    
    print("\tsaiu do automa!!")

def old_automa(blocks, trans):
    global endTime
    global startTime
    time.sleep(5)
    for blk in range(0, blocks):
        newKeyPair()
        counter = 0
        while(addBlockOnChain()==False):
            logger.error("ERROR: creating a new key pair and trying to create a new block")
            newKeyPair()
            counter= counter + 1
            if (counter > 10):
                break

        # brutePairAuth(blk)
        startTime = (time.time()) * 1000 * 1000
        for tr in range(0, trans):
            logger.info("Sending transaction #" + str(tr) + "...")
            # sendData()
            while (not (server.isBlockInTheChain(publicKey))):
                time.sleep(0.0001)
                continue
                # time.sleep(1)
            bruteSend(tr)
    endTime = (time.time()) * 1000 * 1000
    logT27.append(
        "Device;" + deviceName + ";T27; Time run all transactions in ms;" + str((endTime - startTime) / 1000))
    time.sleep(60)

def simulateDevices(blocks,trans,mode):
    global trInterval
    # print("\tentrou no simulate devices!!")
    if(mode=="sequential"):
        # print("entrou no sequential")
        for tr in range(0, trans):
            t1 = time.time()
            for blk in range(0, blocks):
                # print("SEQUENTIAL"+str(tr)+"transaction sent")
                simDevBlockAndTransSequential(blk,tr)
            t2= time.time()
            if ((t2 - t1) * 1000 < trInterval):
                time.sleep((trInterval - ((t2 - t1) * 1000)) / 1000)
            if (tr % 10 == 0):
                # print("XTransactions")
                server.saveXTransactionsSizes()
        # print("saving timesSizes")
        server.saveTimesSizes()
        # return
        
    if(mode==lifecycleMultiMode):
        for tr in range(0, trans):
            for i in range(4):
                t1 = time.time()
                for blk in range(0, blocks):
                    simDevBlockAndTransMulti(blk,tr,i)
                t2= time.time()
                if ((t2 - t1) * 1000 < trInterval):
                    time.sleep((trInterval - ((t2 - t1) * 1000)) / 1000)

    else:
        arrayDevicesThreads = []*blocks
        for blk in range(0, blocks):
            logger.info("Adding block #" + str(blk) + "...")
            # for parallel devices use threading option
            arrayDevicesThreads.append(threading.Thread(target=simDevBlockAndTrans, args=(blk, trans)))
            arrayDevicesThreads[blk].start()
            # for sequential devices insertion use method seqDevSim()
        for blk in range(0, blocks):
            arrayDevicesThreads[blk].join()



def merkle():
    """ Calculates the hash markle tree of the block """
    # s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    blk = int(input("Which block you want to create the merkle tree:"))
    server.calcMerkleTree(blk)  # addBlockConsensusCandiate
    # print ("done")
    # s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


def newElection():
    server.electNewOrchestrator()
    return True
    # s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) ###WHAT???###


def defineInteractiveConsensus():
    receivedConsensus = str(input('Set a consensus ("None", "PBFT", "PoW", "dBFT" or "Witness3") (None is default) : '))
    # print("after receiving consensus string: "+receivedConsensus)
    while(not(receivedConsensus == "None" or receivedConsensus == "PBFT" or receivedConsensus == "dBFT" or receivedConsensus == "PoW" or receivedConsensus == "Witness3")):
        receivedConsensus = str(
            input('Not a consensus, type again... Set a consensus ("None", "PBFT", "PoW", "dBFT" or "Witness3") (None is default) : '))
    server.setConsensus(receivedConsensus)
    return True


def defineConsensus(receivedConsensus):
    #receivedConsensus = str(input('Set a consensus (None, PBFT, PoW, dBFT or Witness3) (None is default) : '))
    # server will set its consensus and send it to all peers
    server.setConsensus(receivedConsensus)
    # print("Consensus " + receivedConsensus + " was defined")
    return True


def createBlockForSC():
    newKeyPair()
    addBlockOnChain()
    while (not (server.isBlockInTheChain(publicKey))):
        continue
        # time.sleep(1)
    firstTransactionSC = '{ "Tipo" : "", "Data": "", "From": "", "To" : "", "Root" : "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421" }'
    sendDataSC(firstTransactionSC)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


def showLastTransactionData():
    blockIndex = int(input('Type the index to show the last transaction data: '))
    lastDataTransactionData = server.showLastTransactionData(blockIndex)
    return lastDataTransactionData


def callEVMInterface():
    # Create a TCP
    # IP socket
    global privateKey
    global publicKey
    # s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #
    # # Coleta o data da ultima transacao um json
    # ultimaTrans = showLastTransactionData()
    # ultimaTransJSON = json.loads(ultimaTrans)

    # print("###Please, insert data to call the Smart Contract###")
    callType = str(input("Type (Exec,Criar,Cham): "))
    data = str(input("Data (binary in hexa): "))
    origin = str(input("From account: "))
    dest = str(input("Destination account: "))
    scInfo = callType+data+origin+dest
    signedData = CryptoFunctions.signInfo(privateKey,scInfo)

    scType = pickle.dumps(callType)
    scData = pickle.dumps(data)
    scFrom = pickle.dumps(origin)
    scDest = pickle.dumps(dest)
    scSignedData = pickle.dumps(signedData)
    scPublicKey = pickle.dumps(publicKey)

    logger.debug("###Printing Signing Sc before sending: "+signedData)

    server.callEVM(scType,scData,scFrom,scDest,scSignedData,scPublicKey)
    # transAtual = json.loads(
    #     '{"Tipo":"%s","Data":"%s","From":"%s","To":"%s"}' % (tipo, data, origin, dest))
    #
    # chamada = '{"Tipo":"%s","Data":"%s","From":"%s","To":"%s","Root":"%s"}' % (
    #     transAtual['Tipo'], transAtual['Data'], transAtual['From'], transAtual['To'], ultimaTransJSON['Root'])
    # #chamada =  '{"Tipo":"%s","Data":"%s","From":null,"To":null,"Root":"%s"}' % (transAtual['Tipo'], transAtual['Data'], ultimaTransJSON['Root'])
    # chamadaJSON = json.loads(chamada)
    #
    # # chamada = '{"Tipo":"Exec","Data":"YAFgQFNgAWBA8w==","From":null,"To":null,"Root":null}'  # Comentar
    # # chamadaJSON = json.loads(chamada)  # Comentar
    #
    # try:
    #     # Tamanho maximo do JSON 6 caracteres
    #     s.connect(('localhost', 6666))
    #     tamanhoSmartContract = str(len(chamada))
    #     for i in range(6 - len(tamanhoSmartContract)):
    #         tamanhoSmartContract = '0' + tamanhoSmartContract
    #     # print("Enviando tamanho " + tamanhoSmartContract + "\n")
    #     # Envia o SC
    #     s.send(tamanhoSmartContract)
    #     time.sleep(1)
    #     # print(json.dumps(chamadaJSON))
    #     s.send(chamada)
    #
    #     # Recebe tamanho da resposta
    #     tamanhoResposta = s.recv(6)
    #     # print("Tamanho da resposta: " + tamanhoResposta)
    #     # Recebe resposta
    #     resposta = s.recv(int(tamanhoResposta))
    #     # print(resposta + "\n")
    #
    #     # Decodifica resposta
    #     respostaJSON = json.loads(resposta)
    #     # print(respsotaJSON['Ret'])
    #
    #     if respostaJSON['Erro'] != "":
    #         logger.Exception("Transacao nao inserida")
    #     elif chamadaJSON['Tipo'] == "Exec":
    #         logger.info("Execucao, sem insercao de dados na blockchain")
    #     else:
    #         transacao = '{ "Tipo" : "%s", "Data": "%s", "From": "%s", "To" : "%s", "Root" : "%s" }' % (
    #             chamadaJSON['Tipo'], chamadaJSON['Data'], chamadaJSON['From'], chamadaJSON['To'], respostaJSON['Root'])
    #         logger.info("Transacao sendo inserida: %s \n" % transacao)
    #         sendDataSC(transacao)
    #         # pass
    #
    # finally:
    #     # print("fim\n")
    #     s.close()
    return True


def evmConnector():
    return True


def executeEVM():
    return True


def loadConnection(nameServerIP, nameServerPort, gatewayName):
    global deviceName
    global lifecycleDeviceName
    """ Load the URI of the connection  """
    # ----> Adicionado por Arruda
    ns = Pyro4.locateNS(host=nameServerIP, port=nameServerPort)
    gatewayURI = ns.lookup(gatewayName)
    #print("gatewayURI = " + str(gatewayURI))
    global server
    # fname = socket.gethostname()
    # text_file = open("localhost", "r")
    # uri = text_file.read()
    # print(uri)
    server = Pyro4.Proxy(gatewayURI)
    # text_file.close()
    # os.remove(fname)
    # ---->
    lifecycleDeviceName = server.getDeviceName()
    #print("Lifecycle name: " + str(lifecycleDeviceName))

    defineConsensus(consensus)
    return gatewayURI

def gwSaveLog():
    server.saveLog()

#############################################################################
#############################################################################
################          Lifecycle Events (Rodrigo)         ################
#############################################################################
#############################################################################

# CPU: Intel(R) Core(TM) i5-10400 CPU @ 2.90GHz   2.90 GHz
# RAM: MEMORIA CORSAIR VENGEANCE LPX, 8GB, 2666MHZ, DDR4
# SSD: SSD KINGSTON A400, 480GB, LEITURA 500MB/S, GRAVACAO 450MB/S
# VID: PLACA DE VIDEO ASUS NVIDIA GEFORCE GTX 1660TI, 6GB GDDR6, 12 Gb/s

def addBlockOnChainMulti():
    """ Take the value of 'publicKey' var, and add it to the chain as a block"""
    global serverAESEncKey
    # print("###addBlockonChain in devicesimulator, publicKey")
    # print(publicKey)
    serverAESEncKey = server.addBlockMulti(publicKey, lifecycleDeviceName)
    if serverAESEncKey == "":
        print("Block already added with this public key")
        logger.error("it was not possible to add block - problem in the key")
        return False
    else:
        # print("###addBlockonChain in devicesimulator, serverAESEncKey")
        # print(serverAESEncKey)
        # while len(serverAESEncKey) < 10:
        #    serverAESEncKey = server.addBlock(publicKey)
        decryptAESKey(serverAESEncKey)
    return True
    # print("###after decrypt aes")

def listBlockHeaderMulti():
    """ Log all blocks """
    server.showIoTLedgerMulti()

def listTransactionsMulti():
    """ Ask for the user to input an index and show all transaction of the block with that index """
    index = input("Which IoT Block do you want to print?")
    status = server.showBlockLedgerMulti(int(index))
    #print (status)

def sendLifecycleEventsAsText():      
    """ send each lifecycle event to be added as transaction
        the data is a plaintext\n
    """
    for i in range(4):
        val, valStr = lifecycleMethods[i]()
        t = ((time.time() * 1000) * 1000)
        timeStr = " {:.0f}".format(t)
        data = timeStr + valStr
        #logger.debug("data = "+data)
        print("")
        print("data "+lifecycleTypes[i]+" ="+valStr+", with time: "+data)

        signedData = CryptoFunctions.signInfo(privateKey, data)
        print ("###Signature lenght: " + str(len(signedData)))
        toSend = signedData + data
        print ("toSend = "+toSend)
        #logger.debug("ServeAESKEY = " + serverAESKey)
        try:
            encobj = CryptoFunctions.encryptAES(toSend, serverAESKey)
        except:
            logger.error("was not possible to encrypt... verify aeskey")
            newKeyPair()
            addBlockOnChain() # this will force gateway to recreate the aes key
            signedData = CryptoFunctions.signInfo(privateKey, data)
            toSend = signedData + data
            encobj = CryptoFunctions.encryptAES(toSend, serverAESKey)
            logger.error("passed through sendData except")
        try:
            print ("encobj = "+encobj)
            res = server.addLifecycleEvent(publicKey, encobj)
            print ("result = "+str(res))

            if i == 0 and val < 1500:
                print("CPU is slow")
            if i == 1 and val < 1400:
                print("RAM is slow")
            if i == 2 and val < 280:
                print("SSD is slow")
            if i == 3 and val < 6:
                print("VID is slow")
        except:
            logger.error("some exception with sendLifecycleEventsAsText now...")

def sendLifecycleEventsAsStructure():    
    """ send each lifecycle event to be added as transaction
        the data will be stored as a LifecycleEvent structure\n
    """
    for i in range(4):
        val, valStr = lifecycleMethods[i]()
        t = ((time.time() * 1000) * 1000)
        timeStr = " {:.0f}".format(t)
        data = timeStr + valStr
        #logger.debug("data = "+data)
        #print("")
        #print("data "+lifecycleTypes[i]+" ="+valStr+", with time: "+data)

        signedData = CryptoFunctions.signInfo(privateKey, data)
        #print ("###Signature lenght: " + str(len(signedData)))
        toSend = signedData + data
        #print ("toSend = "+toSend)
        #logger.debug("ServeAESKEY = " + serverAESKey)
        try:
            encobj = CryptoFunctions.encryptAES(toSend, serverAESKey)
        except:
            logger.error("was not possible to encrypt... verify aeskey")
            newKeyPair()
            addBlockOnChain() # this will force gateway to recreate the aes key
            signedData = CryptoFunctions.signInfo(privateKey, data)
            toSend = signedData + data
            encobj = CryptoFunctions.encryptAES(toSend, serverAESKey)
            logger.error("passed through sendLifecycleEventsAsStructure except")
        try:
            #print ("encobj = "+encobj)
            res = server.addLifecycleEventStructure(publicKey, encobj, lifecycleTypes[i])
            #print ("result = "+str(res))
        except:
            logger.error("some exception with sendLifecycleEventsAsStructure now...")

def sendLifecycleEventsMulti():
    """
    All "Multi" methods are related to multiple transaction chains
    """
    for i in range(4):
        val, valStr = lifecycleMethods[i]()
        t = ((time.time() * 1000) * 1000)
        timeStr = " {:.0f}".format(t)
        data = timeStr + valStr
        #logger.debug("data = "+data)
        #print("")
        #print("data "+lifecycleTypes[i]+" ="+valStr+", with time: "+data)

        signedData = CryptoFunctions.signInfo(privateKey, data)
        #print ("###Signature lenght: " + str(len(signedData)))
        toSend = signedData + data
        #print ("toSend = "+toSend)
        #logger.debug("ServeAESKEY = " + serverAESKey)
        try:
            encobj = CryptoFunctions.encryptAES(toSend, serverAESKey)
        except:
            logger.error("was not possible to encrypt... verify aeskey")
            newKeyPair()
            addBlockOnChainMulti() # this will force gateway to recreate the aes key
            signedData = CryptoFunctions.signInfo(privateKey, data)
            toSend = signedData + data
            encobj = CryptoFunctions.encryptAES(toSend, serverAESKey)
            logger.error("passed through sendLifecycleEventsMulti except")
        try:
            #print ("encobj = "+encobj)
            res = server.addLifecycleEventMulti(publicKey, encobj, i, lifecycleTypes[i])
            #print ("result = "+str(res))
        except:
            logger.error("some exception with sendLifecycleEventsMulti now...")

def sendEventMulti(event, chainIndex):
    """
    All "Multi" methods are related to multiple transaction chains
    """
    t = ((time.time() * 1000) * 1000)
    timeStr = " {:.0f}".format(t)
    data = timeStr + event
    #logger.debug("data = "+data)
    #print("")
    #print("data "+lifecycleTypes[i]+" ="+valStr+", with time: "+data)

    signedData = CryptoFunctions.signInfo(privateKey, data)
    #print ("###Signature lenght: " + str(len(signedData)))
    toSend = signedData + data
    #print ("toSend = "+toSend)
    #logger.debug("ServeAESKEY = " + serverAESKey)
    try:
        encobj = CryptoFunctions.encryptAES(toSend, serverAESKey)
    except:
        logger.error("was not possible to encrypt... verify aeskey")
        newKeyPair()
        addBlockOnChainMulti() # this will force gateway to recreate the aes key
        signedData = CryptoFunctions.signInfo(privateKey, data)
        toSend = signedData + data
        encobj = CryptoFunctions.encryptAES(toSend, serverAESKey)
        logger.error("passed through sendLifecycleEventsMulti except")
    try:
        #print ("encobj = "+encobj)
        res = server.addLifecycleEventMulti(publicKey, encobj, chainIndex, "", False)
        #print ("result = "+str(res))
    except:
        logger.error("some exception with sendLifecycleEventsMulti now...")

def sendLifecycleEventsSingle():
    """
    All "Single" methods are related to a single transaction chain
    """
    encobj = []
    for i in range(4):
        val, valStr = lifecycleMethods[i]()
        t = ((time.time() * 1000) * 1000)
        timeStr = " {:.0f}".format(t)
        data = timeStr + valStr
        #logger.debug("data = "+data)
        #print("")
        #print("data "+lifecycleTypes[i]+" ="+valStr+", with time: "+data)

        signedData = CryptoFunctions.signInfo(privateKey, data)
        #print ("###Signature lenght: " + str(len(signedData)))
        toSend = signedData + data
        #print ("toSend = "+toSend)
        #logger.debug("ServeAESKEY = " + serverAESKey)
        try:
            encobj.append(CryptoFunctions.encryptAES(toSend, serverAESKey))
            #print("Succesfully encrypted")
        except:
            logger.error("was not possible to encrypt... verify aeskey")
            newKeyPair()
            addBlockOnChain() # this will force gateway to recreate the aes key
            signedData = CryptoFunctions.signInfo(privateKey, data)
            toSend = signedData + data
            encobj[i] = CryptoFunctions.encryptAES(toSend, serverAESKey)
            logger.error("passed through sendLifecycleEventsSingle except")
    try:
        #print ("encobj = "+encobj)
        res = server.addLifecycleEventSingle(publicKey, encobj, lifecycleTypes)
        #print ("result = "+str(res))
    except:
        logger.error("some exception with sendLifecycleEventsMulti now...")

def readSpeedCPU():
    """ Generates random data like '1700MHz' """
    cpu = random.randint(1400, 2900)
    cpuStr = " " + str(cpu) + "MHz"
    return cpu, cpuStr

def readSpeedRAM():
    """ Generates random data like '2300MHz' """
    ram = random.randint(1300, 2666)
    ramStr = " " + str(ram) + "MHz"
    return ram, ramStr

def readSpeedSSD():
    """ Generates random data like '300MB/s' """
    ssd = random.randint(250, 500)
    ssdStr = " " + str(ssd) + "MB/s"
    return ssd, ssdStr

def readSpeedVid():
    """ Generates random data like '7GB/s' """
    video = random.randint(5, 12)
    videoStr = " " + str(video) + "GB/s"
    return video, videoStr

def storeChainToFile():
    """ store the entire chain to a text file\n
    """
    server.storeChainToFile()

    return True

def restoreChainFromFile():
    """ restore the entire chain from a text file\n
    """
    timeToRestore = server.restoreChainFromFile()
    print("Time to restore all blocks and transactions from file: " + timeToRestore)

    return True

def listBlocksWithId():
    deviceId = str(input("Which device ID do you want to search on blocks?")).strip()
    status = server.showBlockWithId(deviceId)
    status = server.showBlockWithIdMulti(deviceId)

def listTransactionsWithId():
    componentId = str(input("Which component ID do you want to search?")).strip()
    listTransactionsWithId2(componentId, False)

def listTransactionsWithId2(componentId, showTransactions, f):
    timeNormal, trCountNormal = server.showTransactionWithId(componentId, showTransactions)
    print("Time to get all " + str(trCountNormal) + " transactions (NORMAL): " + str(timeNormal))
    timeMulti, trCountMulti = server.showTransactionWithIdMulti(componentId, showTransactions)
    print("Time to get all " + str(trCountMulti) + " transactions (MULTI): " + str(timeMulti))
    if f != False:
        f.write("Time to get all " + str(trCountNormal) + " transactions with id " + str(
            componentId) + " (NORMAL): " + str(timeNormal) + "\n")
        f.write("Time to get all " + str(trCountMulti) + " transactions with id " + str(
            componentId) + " (MULTI): " + str(timeMulti) + "\n")

def automateLifecycleEvents():
    gatewayUriA = loadConnection(nameServerIP, nameServerPort, gatewayName)
    gatewayUriB = loadConnection(nameServerIP, nameServerPort, "gwb")
    gatewayUriC = loadConnection(nameServerIP, nameServerPort, "gwc")
    gatewayUriD = loadConnection(nameServerIP, nameServerPort, "gwd")
    
    diferentBlocks = 10
    blocks = 1
    transactions = 500

    print("Creating Lifecycle events automatically, with " + str(
        diferentBlocks * blocks) + " blocks for each device and " + str(
        transactions) + " for each block\n")
    t1 = time.time()
    tNormal = 0
    tMulti = 0
    for i in range(diferentBlocks):
        setServerWithUri(gatewayUriA)

        t3 = time.time()
        automateLifecycleEventsNormal(blocks, transactions)
        tNormal = tNormal + time.time() - t3
        t3 = time.time()
        automateLifecycleEventsMulti(blocks, transactions)
        tMulti = tMulti + time.time() - t3
        setServerWithUri(gatewayUriB)
        t3 = time.time()
        automateLifecycleEventsNormal(blocks, transactions)
        tNormal = tNormal + time.time() - t3
        t3 = time.time()
        automateLifecycleEventsMulti(blocks, transactions)
        tMulti = tMulti + time.time() - t3
        setServerWithUri(gatewayUriC)
        t3 = time.time()
        automateLifecycleEventsNormal(blocks, transactions)
        tNormal = tNormal + time.time() - t3
        t3 = time.time()
        automateLifecycleEventsMulti(blocks, transactions)
        tMulti = tMulti + time.time() - t3
        setServerWithUri(gatewayUriD)
        t3 = time.time()
        automateLifecycleEventsNormal(blocks, transactions)
        tNormal = tNormal + time.time() - t3
        t3 = time.time()
        automateLifecycleEventsMulti(blocks, transactions)
        tMulti = tMulti + time.time() - t3
    
    # f = open('trans_normal.txt', "a")
    # timeDiff = '{0:.12f}'.format(tNormal * 1000)
    # f.write("Time to create all transactions: " + str(timeDiff) + "\n\n")
    # f.close()
    # f = open('trans_multi.txt', "a")
    # timeDiff = '{0:.12f}'.format(tMulti * 1000)
    # f.write("Time to create all transactions: " + str(timeDiff) + "\n\n")
    # f.close()

    t2 = time.time()
    timeDiff = '{0:.12f}'.format((t2 - t1) * 1000)
    print("Time to create all blocks and transactions: " + str(timeDiff))

    # print("Store chains to file")
    storeChainToFile()

    f = open('recovery_time.txt', "a")
    f.write("Time to create all blocks and transactions: " + str(timeDiff) + "\n")

    componentId = "SN1234_RAM_dev-gwc"
    print("Getting all transactions for component = " + str(componentId))
    listTransactionsWithId2(componentId, False, f)

    componentId = "SN1234_CPU_dev-gwa"
    print("Getting all transactions for component = " + str(componentId))
    listTransactionsWithId2(componentId, False, f)
    f.write("\n")
    f.close()

    print("saving Gw logs")
    try:
        gwSaveLog()
    except:
        print("another is saving the logs")
    print("Saved Gw logs, now saving Dev logs")
    saveDeviceLog()
    
    #listBlockHeader()
    #listBlockHeaderMulti()

def automateLifecycleEventsNormal(blocks, transactions):
    for b in range(blocks):
        #print("Create key pair NORMAL " + str(b))
        newKeyPair()
        #time.sleep(1)
        #print("Create block NORMAL " + str(b))
        ret = addBlockOnChain()
        #time.sleep(2)
        if ret:
            for t in range(transactions):
                #print("Create transaction NORMAL " + str(t) + " for block " + str(b))
                sendLifecycleEventsAsStructure()
                #time.sleep(1)
    
def automateLifecycleEventsMulti(blocks, transactions):
    for b in range(blocks):
        #print("Create key pair MULTI " + str(b))
        #print("public key: " + str(publicKey))
        #print("private key: " + str(privateKey))
        newKeyPair()
        #print("public key: " + str(publicKey))
        #print("private key: " + str(privateKey))
        #time.sleep(1)
        #print("Create block MULTI " + str(b))
        ret = addBlockOnChainMulti()
        #time.sleep(2)
        if ret:
            for t in range(transactions):
                #print("Create transaction MULTI " + str(t) + " for block " + str(b))
                sendLifecycleEventsMulti()
                #time.sleep(1)

# for parallel simulation of devices and insertions use this
def simDevBlockAndTransMulti(blk, trans, index):
    numTrans = trans
    # trInterval is amount of time to wait before send the next tr in ms
    global trInterval
    global startTime
    global keysArray

    if (trans == 0 and index == 0):
        devPubK, devPrivK = CryptoFunctions.generateRSAKeyPair()
        counter = 0
        AESKey = addBlockOnChainMultiV2(devPubK, devPrivK)
        keysArray.append([devPubK, devPrivK, AESKey])
        while (AESKey == False):
            logger.error("ERROR: creating a new key pair and trying to create a new block")
            devPubK, devPrivK = CryptoFunctions.generateRSAKeyPair()
            AESKey = addBlockOnChainMultiV2(devPubK, devPrivK)
            keysArray[blk]=[devPubK, devPrivK, AESKey]
            counter = counter + 1
            if (counter > 10):
                break
        if (startTime==0):
            startTime = (time.time())*1000*1000
    # t1 = time.time()

    devPubK=keysArray[blk][0]
    devPrivK=keysArray[blk][1]
    AESKey=keysArray[blk][2]
    while (not (server.isBlockInTheChainMulti(devPubK))):
        time.sleep(0.001)
        # continue
        # time.sleep(1)
    devPubK, devPrivK, AESKey = multSendMulti(devPubK, devPrivK, AESKey, trans, blk, index)
    if (AESKey != False):
        keysArray[blk][2]=AESKey
    # t2 = time.time()
    #
    # if ((t2 - t1) * 1000 < trInterval):
    #     t2 = time.time()
    #     # trInterval is in ms and time.sleep is in s, so you should divide by 1000
    #     time.sleep((trInterval - ((t2 - t1) * 1000)) / 1000)

def addBlockOnChainMultiV2(devPubKey, devPrivKey):
    """ Take the value of 'publicKey' var, and add it to the chain as a block"""
    # print("###addBlockonChain in devicesimulator, publicKey")
    # print(publicKey)
    # pickedDevPubKey = pickle.dumps(devPubKey)
    serverAESEncKey = server.addBlockMulti(devPubKey, lifecycleDeviceName)
    if (len(str(serverAESEncKey))<10):
        logger.error("it was not possible to add block - problem in the key")
        return False
    # print("###addBlockonChain in devicesimulator, serverAESEncKey")
    # print(serverAESEncKey)
    # while len(serverAESEncKey) < 10:
    #    serverAESEncKey = server.addBlock(publicKey)
    try:
        AESKey = CryptoFunctions.decryptRSA2(devPrivKey, serverAESEncKey)
    except:
        logger.error("problem decrypting the AES key")
        return False
    return AESKey

def multSendMulti(devPubK, devPrivateK, AESKey, trans, blk, index):
    try:
        return sendDataArgsMulti(devPubK, devPrivateK, AESKey, trans, blk, index)
    except KeyboardInterrupt:
        sys.exit()
    except:
        logger.error("failed to execute send tr:" + str(trans)+"from Blk: "+ str(blk))
        exc_type, exc_value, exc_traceback = sys.exc_info()
        logger.error("*** print_exception:\n" + str(
            traceback.print_exception(exc_type, exc_value, exc_traceback, limit=2, file=sys.stdout)))
        # global serverAESKey
        # print("the size of the serverAESKey is: "+str(len(serverAESKey)))
        # time.sleep(0.001)
        return False  # addBlockConsensusCandiate

def sendDataArgsMulti(devPubK, devPrivateK, AESKey, trans, blk, index):
    """ Read the sensor data, encrypt it and send it as a transaction to be validated by the peers """
    global logT30
    global logT31
    global keysArray
    val, valStr = lifecycleMethods[index]()
    t = ((time.time() * 1000) * 1000)
    timeStr = " {:.0f}".format(t)
    data = timeStr + valStr
    #logger.debug("data = "+data)
    signedData = CryptoFunctions.signInfo(devPrivateK, data)
    toSend = signedData + data

    try:
        encobj = CryptoFunctions.encryptAES(toSend, AESKey)
        t2 = ((time.time() * 1000) * 1000)
        logT30.append("Device;" + deviceName + ";T30; Time to create a transaction;" + str((t2 - t) / 1000))
        # print(("Device;" + deviceName + ";T30; Time to create a transaction;" + str((t2 - t) / 1000)))

    except:
        logger.error("was not possible to encrypt... verify aeskey: "+ str(AESKey) +" in blk: " + str(blk) + "tr: " + str(trans))
        logger.info("ERROR: was not possible to encrypt... verify aeskey: "+ str(AESKey) +" in blk: " + str(blk) + "tr: " + str(trans))
        devPubK, devPrivateK = CryptoFunctions.generateRSAKeyPair()
        AESKey = addBlockOnChainMultiV2(devPubK, devPrivateK) # this will force gateway to recreate the aes key
        # logger.error("New aeskey is: "+ str(AESKey))
        t = ((time.time() * 1000) * 1000)
        timeStr = "{:.0f}".format(t)
        data = timeStr + valStr
        signedData = CryptoFunctions.signInfo(devPrivateK, data)
        toSend = signedData + data
        encobj = CryptoFunctions.encryptAES(toSend, AESKey)
        t2 = ((time.time() * 1000) * 1000)
        logT30.append("Device;" + deviceName + ";T30; Time to create a transaction;" + str((t2 - t) / 1000))
        # print(("Device;" + deviceName + ";T30; Time to create a transaction;" + str((t2 - t) / 1000)))
        logger.error("passed through sendDataArgsMulti except")
        logger.info("ERROR: passed through sendDataArgsMulti except")
    try:
        encobj=pickle.dumps(encobj)
        devPubK = pickle.dumps(devPubK)
        lifecycleType=pickle.dumps(lifecycleTypes[index])
        index = pickle.dumps(index)
        transactionStatus= server.addTransactionToPoolMulti(devPubK, encobj, lifecycleType, index)
        t3 = ((time.time() * 1000) * 1000)
        logT31.append("Device;" + deviceName + ";T31; Time to send/receive a transaction;" + str((t3 - t2) / 1000))
        # print("Device;" + deviceName + ";T31; Time to send/receive a transaction;" + str((t3 - t2) / 1000))
        #logger.info("Device;" + deviceName + ";T31; Time to send/receive a transaction;" + str((t3 - t2) / 1000))
        if(transactionStatus=="ok!"):
            # logger.error("everything good now")
            return devPubK,devPrivateK,AESKey
        else:
            # logger.error("Used AESKey was: " + str(AESKey))
            logger.error("something went wrong when sending data in blk Multi: " + str(blk) + " tr: " + str(trans))
            logger.error("Transaction status problem Multi: " + transactionStatus)
            return devPubK,devPrivateK,AESKey
    except:
        logger.error("some exception with addTransactionToPoolMulti now...in blk: " + str(blk) + " tr: " + str(trans))
        logger.info("ERROR: some exception with addTransactionToPoolMulti now...in blk: " + str(blk) + " tr: " + str(trans))
        return devPubK,devPrivateK,AESKey

def changeComponents():
    # Change the target component from this Device to a new one and put the old component to an other Device
    gwUri = str(input("Which is the device URI that will receive the component? (gateway URI)")).strip()
    comp = str(input("Which component? (SSD, RAM, VID or CPU)")).strip()
    type = str(input("What is the chain type? (0-default, 1-MultiChains, 2-SingleStructure)")).strip()
    
    if type == 1:
        chainIndex = 0
        for lt in range(lifecycleTypes):
            if lifecycleTypes[lt] == str(comp):
                chainIndex = lt

        compId = server.getComponentNameByType(comp)
        sendEventMulti("Removing old component: " + str(compId), chainIndex)
        newCompId = compId + "_NEW"
        sendEventMulti("Adding new component: " + str(newCompId), chainIndex)
        server.updateComponentNameByType(comp, newCompId)

        setServerWithUri(gwUri)
        compId2 = server.getComponentNameByType(comp)
        sendEventMulti("Removing old component: " + str(compId2), chainIndex)
        sendEventMulti("Adding new component: " + str(compId), chainIndex)
        server.updateComponentNameByType(comp, compId)
        
        setServerWithUri(gatewayURI)

#############################################################################
#############################################################################
######################          Main         ################################
#############################################################################
#############################################################################

def showkeys():
    print("deviceName {} keys:".format(deviceName))
    print("publicKey \n{}".format(publicKey))
    print("privateKey: \n{}".format(privateKey))

def testsignverify():
    global logCreateSignTime
    global logVerifySignTime
    global logSignSize
    data = b"um dado qualquer"
    t1 = time.time()
    sig = CryptoFunctions.signInfo(privateKey,data)
    t2 = time.time()
    logCreateSignTime.append("SignatureCreate;"+ signatureAlgoritm + ";{0:.12f};ms".format((t2 - t1) * 1000))
    print("sign logged")
    signSize = len(sig)
    logSignSize.append("signatureSize"+ signatureAlgoritm+";"+ str(signSize) + ";Bytes"+ ";data in test sign" )
    print("size logged")
    veri = CryptoFunctions.signVerify(data,sig,publicKey)
    t3 = time.time()
    logVerifySignTime.append("SignatureVerify;"+ signatureAlgoritm + ";{0:.12f};ms".format((t3 - t2) * 1000))
    print("verify logged")
    if veri:
        print("assinatura verificada com sucesso!!")
    else:
        print("assinatura com erros!!")
        
def saveTimesSizes():
    global logCreateSignTime
    global logVerifySignTime
    global logSignSize
    global logCreateTransactTime
    global logTransactSize
    global logXTransactSize
    
    numberGateways = 10
    numberTransactions = 10
    numberBlocks = 50
    
    directory = "./results"
    filename = deviceName+"-"+str(datetime.now())+".logs"
    filepath = os.path.join(directory,filename)
    
    if not os.path.exists(directory):
        print("creating diretory in dv")
        os.makedirs(directory)
    
    with open(filepath,'w') as file:
        file.write("#######################################################################")
        file.write("Runtime infos")
        file.write("Number of Gateways: "+numberGateways)
        file.write("Number of Transactions: "+numberTransactions)
        file.write("Number of Blocks: "+numberBlocks)
        file.write("Consensus: PBFT")
        file.write("#######################################################################")
    
        logger.info("#############################################################")
        logger.info("###################### Times & Sizes ########################")
        logger.info("#############################################################")
        file.write("#############################################################\n")
        file.write("###################### Times & Sizes ########################\n")
        file.write("#############################################################\n")
        
        for i in range(len(logCreateSignTime)):
            logger.info(logCreateSignTime[i])
            file.write(logCreateSignTime[i] + '\n')
        print("Log logCreateSignTime saved")
        logCreateSignTime = []
        
        for i in range(len(logVerifySignTime)):
            logger.info(logVerifySignTime[i])
            file.write(logVerifySignTime[i] + '\n')
        print("Log logVerifySignTime saved")
        logVerifySignTime = []
        
        for i in range(len(logSignSize)):
            logger.info(logSignSize[i])
            file.write(logSignSize[i] + '\n')
        print("Log logSignSize saved")
        logSignSize = []
        
        for i in range(len(logCreateTransactTime)):
            logger.info(logCreateTransactTime[i])
            file.write(logCreateTransactTime[i] + '\n')
        print("Log logCreateTransactTime saved")
        logCreateTransactTime = []
        
        for i in range(len(logTransactSize)):
            logger.info(logTransactSize[i])
            file.write(logTransactSize[i] + '\n')
        print("Log logTransactSize saved")
        logTransactSize = []
        
        # for i in range(len(logXTransactSize)):
        #     logger.info(logXTransactSize[i])
        #     file.write(logXTransactSize[i] + '\n')
        # print("Log logXTransactSize saved")
        # logXTransactSize = []
        logger.info("#############################################################")
        file.write("#############################################################")
        # Save the logs in the server too
    server.saveTimesSizes()


def InteractiveMain():
    """ Creates an interactive screen for the user with all option of a device"""
    global server

    options = {
        1: setServer,
        2: addPeer,
        3: addBlockOnChain,
        4: sendData,
        5: listBlockHeader,
        6: listTransactions,
        7: listPeers,
        8: newKeyPair,
        9: defineAutomaNumbers,
        10: merkle,
        11: newElection,
        12: defineInteractiveConsensus,
        13: createBlockForSC,
        14: showLastTransactionData,
        15: callEVMInterface,
        # 16: evmConnector,
        # 17: executeEVM,
        17: defineContextsAutomaNumbers,
        18: gwSaveLog,
        19: storeChainToFile,
        20: restoreChainFromFile,
        21: addBlockOnChainMulti,
        22: listBlockHeaderMulti,
        23: listTransactionsMulti,
        24: sendLifecycleEventsAsText,
        25: sendLifecycleEventsAsStructure,
        26: sendLifecycleEventsMulti,
        27: listBlocksWithId,
        28: listTransactionsWithId,
        29: automateLifecycleEvents,
        30: sendLifecycleEventsSingle,
        31: changeComponents,
        32: showkeys,
        33: testsignverify,
        34: saveTimesSizes,
    }

    mode = -1
    while True:
        print("Choose your option [" + str(server) + "]")
        print("#############################################################")
        print("0 - Exit")
        print("1 - Set Server Address[ex:PYRO:chain.server@blablabala:00000]")
        print("2 - Add Peer")
        print(
            "3 - Authentication Request [a)Gw Generate AES Key;b)Enc key with RSA;c)Dec AES Key]")
        print("     AKA: Add block on chain")
        print(
            "4 - Produce Data [a)sign data;b)encrypt with AES key;c)Send to Gateway;d)GW update ledger and peers")
        print("5 - List Block Headers from connected Gateway")
        print("6 - List Transactions for a given Block Header")
        print("7 - List PEERS")
        print("8 - Recreate Device KeyPair")
        print("9 - Run a batch operation...")
        print("10 - Create Merkle Tree for a given block")
        print(
            "11 - Elect a new node as Orchestator (used for voting based consensus")
        print("12 - Set a consensus algorithm")
        print("13 - Create a block for Smart Contract")
        print("14 - Show data from last transaction from block Index")
        print("15 - Call Smart Contract")
        # print("16 - EVM connector")
        print("17 - Define number of Contexts, Devices per Gw, and Tx per Device")
        print("18 - Save Gw log T20")
        print("19 - Store the entire chain to a file")
        print("20 - Restore the entire chain from a file")
        print("21 - Add block on chain with multiple transactions chains")
        print("22 - List Block Headers with multiple transactions chains from connected Gateway")
        print("23 - List Transactions from multiple chains for a given Block Header")
        print("24 - Send all lifecycle events as text to block, one transaction for each data")
        print("25 - Send all lifecycle events as a structure to block, one transaction for each data")
        print("26 - Send all lifecycle events as a structure to block, one transaction on each transaction chain")
        print("27 - Get blocks by device ID (e.g.: dev-gwa)")
        print("28 - Get transactions by component ID (e.g.: SN1234_VID_dev-gwa)")
        print(
            "29 - Automatically create X blocks for each device with Y transactions for each component (X and Y should be changed on code)")
        print("30 - Send all lifecycle events as a structure to block, a single transaction with all components")
        print("31 - Change components between devices")
        print("32 - Show device keys")
        print("33 - Test sign & verify")
        print("34 - Save times & sizes logs")
        print("#############################################################")


        try:
            mode = int(input('Input:'))
        except:
            print ("Not a number")
            mode = -1

        if (mode == 0):
            print("See you soon, Thanks for using SpeedyChain =) ")
            print("Powered by CONSEG group")
            break
        try:
            options[mode]()
            print ("")      # Just print a new line 
        except:
            print("Not a valid input, try again")
            mode = -1

if __name__ == '__main__':

    # if len(sys.argv[1:]) > 1:
        # ----> Adicionado por Arruda
        # print ("Command Line usage:")
        # print (
        #     "    python deviceSimulator.py <name server IP> <gateway name> <blocks> <transactions>")
        # ---->
        # os.system("clear")
        # print("running automatically")
    global trInterval
    global lifecycleMethods
    global lifecycleTypes
    
    #generate the keys
    global privateKey
    global publicKey
    publicKey,privateKey = CryptoFunctions.generateRSAKeyPair()

    lifecycleTypes = ["CPU", "RAM", "SSD", "VID"]
    lifecycleMethods = [readSpeedCPU, readSpeedRAM, readSpeedSSD, readSpeedVid]
    if len(sys.argv[1:])<4:
        print("Command line syntax:")
        print("  python DeviceSimulator.py <name server IP> <name server port> <gateway name> <device name>")
    else:
        nameServerIP = sys.argv[1]
        nameServerPort = int(sys.argv[2])
        gatewayName = sys.argv[3]
        deviceName = sys.argv[4]
        logger = Logger.configure(deviceName + ".log")
        logger.info("Running device " + deviceName + " in " + getMyIP())



        if (len(sys.argv) < 6): #when it is not called with number of blocks/transactions and consensus, it is called interactive mode
            consensus = "PBFT"
            gatewayURI = loadConnection(nameServerIP, nameServerPort, gatewayName)

            logger.info("Connected to gateway: " + gatewayURI.asString())
            InteractiveMain()
        else:


            blocks = sys.argv[5]
            transactions = sys.argv[6]
            consensus = sys.argv[7]
            numContexts = sys.argv[8]
            trInterval = int(sys.argv[9])
            #print("arg size = " + str(len(sys.argv[1:])))
            if len(sys.argv[1:])==10:
                mode = sys.argv[10]
            else:
                mode = "sequential"

            gatewayURI = loadConnection(nameServerIP, nameServerPort, gatewayName)

            logger.info("Connected to gateway: " + gatewayURI.asString())
            # setContexts(int(numContexts))
            time.sleep(10)
            logger.info("Processing " + blocks + " blocks and " + transactions + " transactions...")
            #print("runtype = " + mode)
            automa(int(blocks), int(transactions), mode)

            # FOR OLD VERSION  - WITHOUT CONSENSUS use old_automa
            # old_automa(int(blocks), int(transactions))
            logger.info("Finishing Execution of Device"+deviceName)

            if deviceName == "dev-a":
                print("Store chain to file...")
                storeChainToFile()
                #listBlockHeader()
                listBlockHeaderMulti()
                componentId = "SN1234_RAM_dev-gwa"
                print("Getting all transactions for component = " + str(componentId))
                timeMulti, trCountMulti = server.showTransactionWithIdMulti(componentId, True)
        # else:
        # os.system("clear")
        # loadConnection()
        # main()
