#!/usr/bin/env python3.7


import sys
import hashlib 
import time
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Hash import SHA256

class network(object):
	def __init__(self):
		# initialize network
		return

class merkeleTree(object):
	def __init__(self,transactions):
		self.leaves = transactions
		self.levelNodes = []

		self.buildTree()

	def buildLevel(self,level):
		if len(level) == 1:
			return 0
		if (level)%2 == 1:
			level += level[-1]
		upper_level = []
		for i in range(len(level)//2):
			upper_level.append(hashlib.sha256(level[i*2]+level[i*2+1]))

		self.levelNodes.append(upper_level)
		return 1

	def buildTree(self,):

		while True:
			inp = self.leaves
			if len(self.levelNodes) != 0:
				inp = self.levelNodes[-1]

			ret = self.buildLevel(inp)
			if ret == 0:
				break





class node(object):

	def __init__(self, iden, public_key=None, private_key=None):
		self.id = iden
		if public_key is not None:
			self.public_key = public_key
			self.__private_key = private_key
		else:
			self.public_key,self.__private_key = self.newkeys()

		self.walletId = self.public_key

		return

	def newkeys(self, keysize=1024):
	   random_generator = Random.new().read
	   key = RSA.generate(keysize, random_generator)
	   private, public = key, key.publickey()
	   return public, private

	def sign(self, hash_message):
		signer = PKCS1_v1_5.new(self.__private_key)
		hash_message = bytes(str(hash_message), 'utf-8')
		signer = PKCS1_v1_5.new(self.__private_key)
		digest = SHA256.new()
		digest.update(hash_message)
		return signer.sign(digest)

class Transaction(object):

	def __init__(self,fromAddress,toAddress,amount):
		self.fromAddress = fromAddress
		self.toAddress = toAddress
		self.amount = amount

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
		self.nonce = 0
		self.currentHash = self.selfhash()
		if not self.transactionValid():
			print("All transactions are not valid in the block\n")

	def __str__(self):
		transactions_details = []
		for x in self.transx:
			transactions_details.append(x.details())
		return "Transaction: "+str(transactions_details)+" \ncurrentHash: "+str(self.currentHash)+" \n previousHash: "+str(self.previousHash) +" \n nonce: " + str(self.nonce)

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

	def __init__(self,difficulty=3):
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
	bitcoin = blockchain()

	nodeA = node(1)
	nodeB = node(2)
	trans = Transaction(nodeA, nodeB, 10)
	trans.signTransaction()
	block1 = block(time.time(), [trans], "")
	bitcoin.addNewBlock(block1)
	bitcoin.printChain()