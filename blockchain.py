
import hashlib 
import time
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Hash import SHA256
import copy


class merkeleTree(object):
	def __init__(self,transactions):
		self.leaves = transactions
		self.levelNodes = []
		self.rootHash = None
		if len(self.leaves) == 0:
			return
		self.buildTree()
		self.rootHash = self.levelNodes[-1][0]

	def buildLevel(self,level,isleaf=False):
		if len(level) == 1 and isleaf==False:
			return 0
		if len(level)%2 == 1:
			level.append(level[-1])
		upper_level = []
		for i in range(len(level)//2):
			upper_level.append(hashlib.sha256((str(level[i*2])+str(level[i*2+1])).encode('utf-8')).hexdigest())

		self.levelNodes.append(upper_level)
		return 1

	def buildTree(self,):

		self.buildLevel(self.leaves,isleaf=True)
		while True:
			ret = self.buildLevel(self.levelNodes[-1])
			if ret == 0:
				break


class Transaction(object):

	def __init__(self,fromAddress,toAddress,amount, creation_time=0):
		self.fromAddress = fromAddress
		self.toAddress = toAddress
		self.amount = amount
		self.creation_time = creation_time

	def details(self):
		return "Sender: " + str(self.fromAddress.id) + " Receiver: " + str(self.toAddress.id) + " Amount:  " + str(self.amount)

	def calculateHash(self):
		return hashlib.sha256((str(self.toAddress)+str(self.fromAddress)+str(self.amount)).encode('utf-8')).hexdigest()

	def signTransaction(self):
		transaction_hash = self.calculateHash()
		self.signature = self.fromAddress.sign(transaction_hash)
		return

	def isValid(self):
		if not self.signature:
			print("Transaction don't have signature\n")
			return False
		signer = PKCS1_v1_5.new(self.fromAddress.public_key)
		hash_message = bytes(self.calculateHash(), 'utf-8')
		digest = SHA256.new()
		digest.update(hash_message)
		return signer.verify(digest, self.signature)



class block(object):

	def __init__(self,timestamp,Transx,previousHash=""):
		self.timestamp = timestamp
		self.transx = Transx
		self.previousHash = previousHash
		self.merkeleTree = merkeleTree(copy.copy(Transx))
		self.merkeleRoot = self.merkeleTree.rootHash
		if Transx:
			assert self.merkeleRoot != None,"merkeleRoot can't be None"

		self.nonce = 0
		self.currentHash = self.selfhash()
		self.nextBlocks = []
		if not self.transactionValid():
			print("All transactions are not valid in the block\n")

	def __str__(self):
		transactions_details = []
		for x in self.transx:
			transactions_details.append(x.details())
		return "Transaction: "+str(transactions_details) +" \ncurrentHash: "+str(self.currentHash)+" \n previousHash: "+str(self.previousHash) +" \n nonce: " + str(self.nonce)

	def selfhash(self):
		return hashlib.sha256((str(self.merkeleRoot) + str(self.nonce) +str(self.timestamp) + str(self.previousHash)).encode('utf-8')).hexdigest()

	def updateHash(self):
		self.currentHash = self.selfhash()

	def set_prev_hash(self, pre_hash):
		self.previousHash = pre_hash

	def get_prev_hash(self):
		return self.previousHash

	def mineBlock(self,difficulty):
		while self.currentHash[0:difficulty] != "0"*difficulty :
			self.nonce += 1
			self.updateHash()

	def transactionValid(self):
		for x in self.transx:
			if not x.isValid():
				return False
		return True

class blockchain(object):

	def __init__(self,difficulty=3):
		self.chain = []
		genesisBlock = self.createGenesisBlock()
		self.chain.append(genesisBlock)
		self.chainRoot = genesisBlock
		self.difficulty = difficulty
		self.pendingTransactions = []

	def createGenesisBlock(self):
		return block(time.time(),[],None)

	def getFarthestLeaf(self, leng, root):
		if(root.nextBlocks == []):
			return leng, root
		else:
			max_len = -1000000000
			return_block = None
			for i in range(len(root.nextBlocks)):
				a,b = self.getFarthestLeaf(leng+1, root.nextBlocks[i])
				if(a >= max_len):
					max_len = a
					return_block = b
			return max_len, return_block

	def getLastBlock(self):
		a,b = self.getFarthestLeaf(0, self.chainRoot)
		return b

	def findBlock(self, hashp, root):
		if(root.currentHash == hashp):
			return True, root
		else:
			for i in range(len(root.nextBlocks)):
				a,b = self.findBlock(hashp, root.nextBlocks[i])
				return a,b
			return False, None

	def addNewBlock(self,newBlock):
		previousHash = newBlock.get_prev_hash()
		a, b = self.findBlock(previousHash, self.chainRoot)
		if(a==True and newBlock not in b.nextBlocks):
			b.nextBlocks.append(newBlock)

	def current_hash(self):
		return self.getLastBlock().currentHash

	def printLongestPaths(self, leng, root):
		if(root.nextBlocks == []):
			return leng, [[root]]
		else:
			max_len = -1000000000
			return_list = []
			for i in range(len(root.nextBlocks)):
				a,b = self.printLongestPaths(leng+1, root.nextBlocks[i])
				if(a > max_len):
					max_len = a
					for j in range(len(b)):
						b[j].insert(0, root)
					return_list = b
				elif(a==max_len):
					for j in range(len(b)):
						b[j].insert(0, root)
						return_list.append(b[j])

			return max_len, return_list

	def printChain(self):
		a, b = self.printLongestPaths(0,self.chainRoot)
		for i in range(len(b)):
			print("Chain: " + str(i))
			for j in range(len(b[i])):
				print(b[i][j])
		print(len(self.chainRoot.nextBlocks))

	def mineTransactions(self,by):
		block = block(time.time(),self.pendingTransactions)
		block.previousHash = self.getLastBlock().currentHash
		block.mineBlock(self.difficulty)
		self.chain.append(block)

	def addTransactions(self,transx):
		if not transx.fromAddress or not transx.toAddress:
			print("invalid Transx")
			return
		if not transx.isValid():
			print("invalid Transx")
			return
		self.pendingTransactions.append(transx)