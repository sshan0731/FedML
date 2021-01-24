import numpy as np
import sys
# sys.path.append('.')
# sys.path.append('./Fed_Secure/FedML')
from fedml_core.secure.primitives.key_agreement import DiffieHellman
from fedml_core.secure.primitives.secret_sharing import *
from fedml_core.secure.primitives.AES_encryption import *
from fedml_core.secure.primitives.pseudorandom_generator import *
from fedml_core.secure.secure_aggregation import *


class secure_aggregation_test:
	def user_drop(self, user_id):
		# Input: 
		# user_id: the user that drops off
		# Simulate user_id drop
		live_user_set.remove(user_id)
		for i in mc:
			if i.user_id == user_id:
				mc.remove(i)
		
		print('Dropped user {}'.format(user_id))

	def test_setup(self, m, R, number_users, t, input = np.ones([3, 9], dtype=int), debug_mode = True): # TODO: Check m, R
		global myserver 
		global mc
		global live_user_set
		self.number_users = number_users
		self.t = t # Threshold
		self.m = m
		self.R = R
		self.debug = False
		live_user_set = set()
		myserver = secure_aggregation_server(R = self.R, m = self.m, t = self.t, n = number_users)
		# Set the base aggregation value to be added on
		myserver.aggregation_input(np.zeros(input.shape[1], dtype=int))
		mc = [] # my client list

		for i in range(self.number_users):
			mc.append(secure_aggregation_user(R = self.R, m = self.m, t = self.t, user_id = i))
			live_user_set.add(i)
		# Initialize the user input x_i
		for i in range(self.number_users):
			mc[i].user_input(input[i])
		print('TEST: passing setup, with a server and {} users \n'.format(number_users))

	def test_round0(self):
		# User generate 
		for i in range(self.number_users):
			mc[i].round0_keys_user_generate()

		# User send data with dropout
		self.user_drop(2)
		print('TEST: round 0, dropping user 2 .....')
		for user in mc: 
			user.round0_keys_user_send(myserver)

		# Server broadcast, user receive
		for user in mc: # Set U1 = {0, 1, 3, 4, 5, 6, 7, 8}
			myserver.round0_keys_server_broadcast(user)
			print('TEST: round0, with a server broadcasting keylist to user {}: a list of (user_id, c_pk, s_pk) FINISHED\n'.format(user.user_id))


	def test_round1(self):
		self.user_drop(0)
		print('TEST: round 1, dropping user 0 .....')

		# User send ciphertext eu,v
		for user in mc: # Set U2 = {1, 3, 4, 5, 6, 7, 8}
			user.round1_cipher_user_send(myserver)
			print('TEST: round1, with a user sending ciphertext (userid:{}) FINISHED\n'.format(user.user_id))

		# Server broadcast ciphertext eu,v
		for user in mc: # Set U2 
			myserver.round1_cipher_server_broadcast(user)


	def test_round2(self):
		self.user_drop(1)
		self.user_drop(3)
		self.user_drop(4)
		print('TEST: round 2, dropping user 1,3,4 .....')

		# User send yu
		for user in mc: # Set U3 = {5, 6, 7, 8}
			user.round2_masked_user_send(myserver)
			print('TEST: round2, with a user sending yu (userid:{}) FINISHED\n'.format(user.user_id))

		# User send yu
		for user in mc: # Set U3
			myserver.round2_masked_server_broadcast(user)

	def test_round3(self):
		# Note: we should not drop users because we assume that we are not in the active adversary mode
		# self.user_drop(5)

		# User send yu
		for user in mc: # Set U4 = {5, 6, 7, 8} 
			myserver.round3_u4_server_broadcast(user)
			print('TEST: round3, with server broadcasting u4 to user {}\n'.format(user.user_id))

	def test_round4(self):
		# Server collect response from users and reconstruct shares
		myserver.round4_shares_server_reconstruct()

if __name__=="__main__":
	s = secure_aggregation_test()
	i = 2
	np.random.seed(i)
	m = 5
	R = 10000
	num_user = 12
	t = 4
	input = np.random.randint(0, R//num_user, [num_user, m])
	aggregate_output = input[5:].sum(0)
	s.test_setup(m, R, num_user, t, input)
	s.test_round0()
	s.test_round1()
	s.test_round2()
	s.test_round3()	
	s.test_round4()
	print('Expected aggregated value: {}, the current result {}'.format(aggregate_output % R, myserver.z))
	assert((myserver.z == aggregate_output).all())
	print('Random test with seed {} passed'.format(i))
