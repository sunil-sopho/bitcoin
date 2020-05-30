import sys

import time

class node(object):

	def __init__(self,index,timestamp,data,previousHash):
		self.index = index
		self.timestamp = timestamp
		self.data = data
		self.previousHash = previousHash

		self.currentHash = self.selfhash()


	def selfhash(self):

		return 0

	def updateHash(self):
		self.currentHash = self.selfhash()

class blockchain(object):

	def __init__(self):
		chain = []
		chain.append(createGenesisBlock())

	def createGenesisBlock(self):
		return node(0,time.time(),None,"")

	def getLastBlock(self):
		return self.chain[-1]

	def addNewBlock(self,newBlock):

		newBlock.previousHash = self.getLastBlock().currentHash
		# recalculate hash for new block

		newBlock.updateHash()
		self.chain.append(newBlock)


if __name__ == '__main__':

	# main function