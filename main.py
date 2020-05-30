import sys
import hashlib 
import time

class block(object):

	def __init__(self,index,timestamp,data,previousHash=""):
		self.index = index
		self.timestamp = timestamp
		self.data = data
		self.previousHash = previousHash
		self.nounce = 0

		self.currentHash = self.selfhash()

	def __str__(self):
		return "index: "+str(self.index)+" \ncurrentHash: "+str(self.currentHash)+" \n previousHash: "+str(self.previousHash) +" \n nounce: " + str(self.nounce)

	def selfhash(self):

		return hashlib.sha256((str(self.index) + str(self.nounce) +str(self.timestamp) + str(self.data) + str(self.previousHash) +str(self.data)).encode('utf-8')).hexdigest()

	def updateHash(self):
		self.currentHash = self.selfhash()

	def mineBlock(self,difficulty):

		while self.currentHash[0:difficulty] != "0"*difficulty :
			self.nounce += 1
			self.updateHash()


class blockchain(object):

	def __init__(self,difficulty=5):
		self.chain = []
		self.chain.append(self.createGenesisBlock())
		self.difficulty = difficulty

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


if __name__ == '__main__':

	# main function
	bitcoin = blockchain()
	block1 = block(1,time.time(),"block 1",)

	bitcoin.addNewBlock(block1)
	# print(bitcoin.chain)
	bitcoin.printChain()