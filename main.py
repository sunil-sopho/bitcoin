import sys
import hashlib 
import time
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Hash import SHA256

class node(object):
	def __init__(self, public_key, private_key):
		self.public_key = public_key
		self.__private_key = private_key
		return

	def sign(self, hash_message):
		signer = PKCS1_v1_5.new(self.__private_key)
		hash_message = bytes(str(hash_message))
		# return signer.sign(hash_message)

		signer = PKCS1_v1_5.new(self.__private_key)
		digest = SHA256.new()
		digest.update(hash_message)
		return signer.sign(digest)


class Transaction(object):
	def __init__(self,fromAddress,toAddress,amount):
		self.fromAddress = fromAddress
		self.toAddress = toAddress
		self.amount = amount

	def calculateHash(self):

		return hashlib.sha256(str(self.toAddress)+str(self.fromAddress)+str(self.amount)).hexdigest()

	def signTransaction(self):
		transaction_hash = self.calculateHash()
		self.signature = self.fromAddress.sign(transaction_hash)
		return

	def isValid(self):
		if not self.signature:
			print("Transaction don't have signature\n")
			return False
		signer = PKCS1_v1_5.new(self.fromAddress.public_key)
		hash_message = bytes(self.calculateHash())
		digest = SHA256.new()
		digest.update(hash_message)
		return signer.verify(digest, self.signature)



class block(object):

	def __init__(self,timestamp,Transx,previousHash=""):
		
		self.timestamp = timestamp
		self.transx = Transx
		self.previousHash = previousHash
		self.nonce = 0

		self.currentHash = self.selfhash()

		if not self.transactionValid():
			print("All transactions are not valid in the block\n")

	def __str__(self):
		return "Transaction: "+str(self.transx)+" \ncurrentHash: "+str(self.currentHash)+" \n previousHash: "+str(self.previousHash) +" \n nonce: " + str(self.nonce)

	def selfhash(self):

		return hashlib.sha256((str(self.transx) + str(self.nonce) +str(self.timestamp) + str(self.previousHash)).encode('utf-8')).hexdigest()

	def updateHash(self):
		self.currentHash = self.selfhash()

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

	def __init__(self,difficulty=5):
		self.chain = []
		self.chain.append(self.createGenesisBlock())
		self.difficulty = difficulty

		self.pendingTransactions = []

	def createGenesisBlock(self):
		return block(time.time(),[],None)

	def getLastBlock(self):
		return self.chain[-1]

	def addNewBlock(self,newBlock):

		newBlock.previousHash = self.getLastBlock().currentHash
		# recalculate hash for new block

		newBlock.mineBlock(self.difficulty)
		self.chain.append(newBlock)
	def printChain(self):
		for x in self.chain:
			print(x)

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


	def newkeys(self, keysize):
	   random_generator = Random.new().read
	   key = RSA.generate(keysize, random_generator)
	   private, public = key, key.publickey()
	   return public, private

if __name__ == '__main__':

	# main function
	bitcoin = blockchain()
	public, private = bitcoin.newkeys(1024)
	nodeA = node(public, private)
	public, private = bitcoin.newkeys(1024)
	nodeB = node(public, private)

	trans = Transaction(nodeA, nodeB, 10)
	trans.signTransaction()
	block1 = block(time.time(), [trans], "")

	bitcoin.addNewBlock(block1)
	# print(bitcoin.chain)
	bitcoin.printChain()