import sys
import hashlib 
import time


class Transaction(object):
	def __init__(self,fromAddress,toAddress,amount):
		self.fromAddress = fromAddress
		self.toAddress = toAddress
		self.amount = amount

	def calculateHash(self):

		return hashlib.sha256(str(self.toAddress)+str(self.fromAddress)+str(self.amount)).hexdigest()

	def signTransaction(self):
		# add signTransaction

		return

	def isValid(self):
		if not self.signature:
			print "Transaction don't have signature"
			return False

		# verify signature



class block(object):

	def __init__(self,timestamp,Transx,previousHash=""):
		
		self.timestamp = timestamp
		self.transx = Transx
		self.previousHash = previousHash
		self.nounce = 0

		self.currentHash = self.selfhash()

	def __str__(self):
		return "Transaction: "+str(self.Transx)+" \ncurrentHash: "+str(self.currentHash)+" \n previousHash: "+str(self.previousHash) +" \n nounce: " + str(self.nounce)

	def selfhash(self):

		return hashlib.sha256((str(self.Transx) + str(self.nounce) +str(self.timestamp) + str(self.previousHash) +str(self.data)).encode('utf-8')).hexdigest()

	def updateHash(self):
		self.currentHash = self.selfhash()

	def mineBlock(self,difficulty):

		while self.currentHash[0:difficulty] != "0"*difficulty :
			self.nounce += 1
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
		return block(0,time.time(),None,"")

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


if __name__ == '__main__':

	# main function
	bitcoin = blockchain()
	block1 = block(1,time.time(),"block 1",)

	bitcoin.addNewBlock(block1)
	# print(bitcoin.chain)
	bitcoin.printChain()