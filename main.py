#!/usr/bin/env python3.7


import sys
import hashlib 
import time
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Hash import SHA256
import threading

from blockchain import blockchain,Transaction,block
import copy

global_lock = threading.Lock()

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
		self.messages = []
		self.transactions = []
		self.lock = threading.Lock()
		self.block_messages = []
		self.block_size = 4
		self.block_lock = threading.Lock()

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

	def transact(self, receiver, amount):
		mess = [0, self.walletId, receiver, amount, time.time()]
		for i in range(len(self.nodes)):
			nodes[i].lock.acquire()
			nodes[i].messages.append(mess)
			nodes[i].lock.release()

	def create_block(self):

		# trans = []
		# temp = []
		# for i in range(len(self.transactions)):
		# 	a = self.transactions[i]
		# 	transaction = Transaction(self.nodes[a[1]], self.nodes[a[2]], a[3], a[4])
		# 	transaction.signTransaction()
		# 	temp.append(transaction)

		# temp.sort(key = lambda x: x.creation_time)

		# for i in range(self.block_size):
		# 	a = temp.pop(0)
		# 	trans.append(a)

		trans = []
		self.transactions.sort(key = lambda x: x[4])
		for i in range(self.block_size):
			a = self.transactions.pop(0)
			transaction = Transaction(self.nodes[a[1]], self.nodes[a[2]], a[3], a[4])
			transaction.signTransaction()
			trans.append(transaction)

		block1 = block(time.time(), trans, "")
		currHash = self.bitcoin.current_hash()
		block1.set_prev_hash(currHash)
		block1.mineBlock(3)
		self.block_lock.acquire()
		if(self.block_messages == []):
			self.block_lock.release()
			self.bitcoin.addNewBlock(block1)
			for i in range(len(self.nodes)):
				if(i!=self.walletId):
				    nodes[i].block_lock.acquire()
				    nodes[i].block_messages.append(block1)
				    nodes[i].block_lock.release()
		else:
			for i in range(len(self.block_messages)):
				self.bitcoin.addNewBlock(self.block_messages[i])	
			self.block_lock.release()


	def run_loop(self, iden, nodes, bitcoin):
		self.walletId = iden
		self.nodes = nodes
		self.bitcoin = bitcoin
		while True:
			global_lock.acquire()
			local_mode = mode
			global_lock.release()
			self.lock.acquire()
			if(self.messages != []):
				mess = self.messages.pop(0)
				self.lock.release()
				if(mess[0] == 0):  #Transaction message
					self.transactions.append(mess)
					while(len(self.transactions) >= self.block_size):
						self.create_block()
			else:
				if(local_mode == 0):
					self.lock.release()
					break
				self.lock.release()
		global_lock.acquire()
		print("Here" + str(self.walletId))
		self.bitcoin.printChain()
		global_lock.release()
		return


def start_threads(thread_id, nodes, bitcoin_copy):
	nodes[thread_id].run_loop(thread_id, nodes, bitcoin_copy)
	return

if __name__ == '__main__':
	mode = 1
	bitcoin = blockchain()
	n = 10
	nodes = []
	for i in range(n):
		nodes.append(node(i))

	th = []
	for i in range(n):
		t = threading.Thread(target=start_threads, args=(i,nodes,copy.deepcopy(bitcoin)))
		t.daemon = True
		th.append(t)
		t.start()

	for i in range(n):
		nodes[i].transact((i+1)%n,10)
		nodes[(i+1)%n].transact((i+2)%n,10)

	time.sleep(5)

	mode = 0
	for i in range(n):
		th[i].join()

	# nodeA = node(1)
	# nodeB = node(2)

	# trans1 = Transaction(nodeA, nodeB, 10)
	# trans1.signTransaction()
	# trans2 = Transaction(nodeA, nodeB, 20)
	# trans2.signTransaction()
	# trans3 = Transaction(nodeB, nodeA, 10)
	# trans3.signTransaction()
	# block1 = block(time.time(), [trans1, trans2, trans3], "")
	# bitcoin.addNewBlock(block1)
	# bitcoin.printChain()