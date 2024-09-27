import time

from .BlockHeaderMulti import BlockHeaderMulti
from ..Transaction import Transaction
from ...tools import CryptoFunctions


BlockHeaderChain = []

##This code manages the chain functions with multiple transaction chains
def startBlockChain():
    """ Add the genesis block to the chain 
    """
    BlockHeaderChain.append(getGenesisBlock())

def createNewBlock(devPubKey, gwPvt, blockContext, consensus, device):
    """ Receive the device public key and the gateway private key then it generates a new block \n
    @param devPubKey - Public key of the requesting device \n
    @param gwPvt - Private key of the gateway \n

    @return BlockHeaderMulti
    """
    previousExpiredBlockHash = "None"
    previousExpiredBlock = findLastSameBlock(device)
    if previousExpiredBlock is not False:
        previousExpiredBlockHash = previousExpiredBlock.hash

    previousBlockSignature = "None"
    if previousExpiredBlockHash is not "None":
        previousBlockSignature = CryptoFunctions.encryptRSA2(previousExpiredBlock.publicKey, previousExpiredBlockHash)

    newBlock = generateNextBlock("new block", devPubKey, getLatestBlock(), gwPvt, blockContext, 
                                 consensus, device, previousExpiredBlockHash, previousBlockSignature)
    ##@Regio addBlockHeader is done during consensus! please take it off for running pbft
    #addBlockHeader(newBlock)
    return newBlock

def addBlockHeader(newBlockHeader):
    """ Receive a new block and append it to the chain \n
    @param newBlockHeader - BlockHeaderMulti
    """
    global BlockHeaderChain
    BlockHeaderChain.append(newBlockHeader)

def addBlockTransaction(block, transaction, index):
    """ Receive a block and add to it a list of transactions \n
    @param block - BlockHeaderMulti \n
    @param transaction - list of transaction \n
    @param index - index of chain of transactions
    """
    block.transactions[index].append(transaction)

def getLatestBlock():
    """ Return the latest block on the chain \n
    @return BlockHeaderMulti
    """
    global BlockHeaderChain
    return BlockHeaderChain[len(BlockHeaderChain) - 1]

def getLatestBlockTransaction(blk, index):
    """ Return the latest transaction on a block \n
    @param blk - BlockHeaderMulti object \n
    @param index - Transaction chain index\n
    @return Transaction
    """
    return blk.transactions[index][len(blk.transactions[index]) - 1]

def blockContainsTransaction(block, transaction, index):
    """ Verify if a block contains a transaction \n
    @param block - BlockHeaderMulti object \n
    @param transaction - Transaction object\n
    @param index - Transaction chain index\n
    @return True - the transaction is on the block\n
    @return False - the transcation is not on the block
    """
    for tr in block.transactions[index]:
        if tr == transaction:
            return True

    return False

def findBlock(key):
    """ Search for a specific block in the chain\n
    @param key - Public key of a block \n
    @return BlockHeaderMulti - found the block on the chain \n
    @return False - not found the block on the chain
    """
    global BlockHeaderChain
    for b in BlockHeaderChain:
        if (b.publicKey == key):
            return b
    return False

def getBlockchainSize():
    """ Return the amount of blocks on the chain \n
    @return int - length of the chain
    """
    global BlockHeaderChain
    return len(BlockHeaderChain)

def getFullChain():
    """ Return the entire chain\nShowing
    @return BlockHeaderMulti[] - list of all blocks on the chain
    """
    return BlockHeaderChain

def getBlockByIndex(index):
    """ Return the block on a specific position of the chain\n
    @param index - desired block position\n
    @return BlockHeaderMulti 
    """
    # global BlockHeaderChain
    # for b in BlockHeaderChain:
    #     if (b.index == index):
    #         return b
    # return False
    if (len(BlockHeaderChain) > index):
        return BlockHeaderChain[index]
    else:
        return False

def getGenesisBlock():
    """ Create the genesis block\n
    @param t - current timestamp\n
    @return BlockHeaderMulti - with the genesis block
    """
    k = """-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAM39ONP614uHF5m3C7nEh6XrtEaAk2ys
LXbjx/JnbnRglOXpNHVu066t64py5xIP8133AnLjKrJgPfXwObAO5fECAwEAAQ==
-----END PUBLIC KEY-----"""
    index = 0
    previousHash = "0"
    nonce = 0
    blockContext = "0000"
    t = 1465154705
    device = "device"
    hash = CryptoFunctions.calculateHash(index, previousHash, t, nonce, k, blockContext, device)
    inf = Transaction.Transaction(0, hash, "0", "0", '', 0)
    blk = BlockHeaderMulti(index, previousHash, t, inf, hash, nonce, k, blockContext, device, "None", "None")
    return blk

def generateNextBlock(blockData, pubKey, previousBlock, gwPvtKey, blockContext, consensus, device, 
                      previousExpiredBlock, previousBlockSignature):
    """ Receive the information of a new block and create it\n
    @param blockData - information of the new block\n
    @param pubKey - public key of the device how wants to generate the new block\n
    @param previouBlock - BlockHeaderMulti object with the last block on the chain\n
    @param gwPvtKey - private key of the gateway\n
    @param consensus - it is specified current consensus adopted
    @return BlockHeaderMulti - the new block
    """
    nextIndex = previousBlock.index + 1    
    nextTimestamp = "{:.0f}".format(((time.time() * 1000) * 1000))
    previousBlockHash = CryptoFunctions.calculateHashForBlock(previousBlock)
    nonce = 0
    nextHash = CryptoFunctions.calculateHash(nextIndex, previousBlockHash, nextTimestamp, 
                                             nonce, pubKey, blockContext, device)
    if(consensus == 'PoW'):
        # PoW nonce difficulty
        difficulty_bits = 12 #2 bytes or 4 hex or 16 bits of zeros in the left of hash
        target = 2 ** (256 - difficulty_bits) #resulting value is lower when it has more 0 in the left of hash
        while ((long(nextHash,16) > target ) and (nonce < (2 ** 32))): #convert hash to long to verify when it achieve difficulty
          nonce=nonce+1
          nextHash = CryptoFunctions.calculateHash(nextIndex, previousBlockHash, nextTimestamp, 
                                                   nonce, pubKey, blockContext, device)
    # print("####nonce = " + str(nonce))
    sign = CryptoFunctions.signInfoECDSA(gwPvtKey, nextHash)
    inf = Transaction.Transaction(0, nextHash, nextTimestamp, blockData, sign, 0)

    return BlockHeaderMulti(nextIndex, previousBlockHash, nextTimestamp, inf, nextHash, 
                            nonce, pubKey, blockContext, device, previousExpiredBlock, previousBlockSignature)

def generateNextBlock2(blockData, pubKey, sign, blockContext, timestamp, nonce, numTransactionChains, 
                       index, device, previousExpiredBlock, previousBlockSignature):
    """ Receive the information of a new block and create it\n
    @param blockData - information of the new block\n
    @param pubKey - public key of the device how wants to generate the new block\n
    @param gwPvtKey - private key of the gateway\n
    @param consensus - it is specified current consensus adopted
    @return BlockHeaderMulti - the new block
    """
    previousBlock = getLatestBlock()
    nextIndex = index
    previousBlockHash = CryptoFunctions.calculateHashForBlock(previousBlock)
    nextHash = CryptoFunctions.calculateHash(nextIndex, previousBlockHash, timestamp, 
                                             nonce, pubKey, blockContext, device)
    inf = Transaction.Transaction(0, nextHash, timestamp, blockData, sign, 0)

    return BlockHeaderMulti(nextIndex, previousBlockHash, timestamp, inf, nextHash, nonce, pubKey, 
                            blockContext, device, previousExpiredBlock, previousBlockSignature, numTransactionChains)

def restartChain():
    """ Clear the entire chain """
    global BlockHeaderChain
    BlockHeaderChain = []
    startBlockChain()

def getBlocksById(id):
    """ Return the blocks with a specific device ID\n
    @param id - Block ID name based on device ID\n
    @return Blocks 
    """
    blocks = []
    global BlockHeaderChain

    for b in BlockHeaderChain:
        if (b.device in id):
            blocks.append(b)
    
    return blocks

def getTransactionsWithId(componentId):
    """ Return the transactions with a specific component ID\n
    @param componentId - Transaction ID name based on component ID\n
    @return Transactions 
    """
    blocks = getBlocksById(componentId)
    transactions = []
    for b in blocks:
        for i in range(b.numTransactionChains):
            if (len(b.transactions[i]) > 1 and b.transactions[i][1].identification == componentId):
                transactions = transactions + b.transactions[i]
    
    return transactions

def findLastSameBlock(deviceId):
    for i in range(len(BlockHeaderChain) - 1, 0, -1):
        if BlockHeaderChain[i].device == deviceId:
            return BlockHeaderChain[i]
    
    return False