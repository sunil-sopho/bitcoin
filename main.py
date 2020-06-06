#!/usr/bin/env python3.7


import sys
import hashlib 
import time
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Hash import SHA256

from blockchain import blockchain,Transaction,block

class network(object):
	def __init__(self):
		# initialize network
		self.allnodes = []
		return

	def join(self,n):
		# here n is the node

		self.allnodes.append(n)

	





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





if __name__ == '__main__':
	bitcoin = blockchain()

	nodeA = node(1)
	nodeB = node(2)
	trans = Transaction(nodeA, nodeB, 10)
	trans.signTransaction()
	block1 = block(time.time(), [trans], "")
	bitcoin.addNewBlock(block1)
	bitcoin.printChain()