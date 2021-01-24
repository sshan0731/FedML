import sys
# sys.path.append('./Fed_Secure/FedML')
import numpy as np
from fedml_core.secure.primitives.key_agreement import DiffieHellman
from fedml_core.secure.primitives.secret_sharing import *
from fedml_core.secure.primitives.AES_encryption import *
from fedml_core.secure.primitives.pseudorandom_generator import *
from binascii import hexlify, unhexlify

class secure_aggregation_server:
	def __init__(self, n, t, m = 10, R = 2048, active_adversary_mode = False):
		# Input:
		# n: number of users
		# k: security parameter #TODO
		# t: threshold value
		# u1, u2, u3: set of users collected in different rounds
		# m, R: Z_R^m is the space where input is sampled - m is the vector length of x
		self.m = m
		self.R = R
		self.u1 = set()
		self.u2 = set()
		self.u3 = set()
		self.u4 = set()
		self.u5 = set()
		self.mode = AES.MODE_GCM
		self.MAX_USER = 10
		self.active_adversary_mode = active_adversary_mode
		self.debug = True 
		self.debug_level = 1
		self.keylist = []
		self.t = t
		self.n = n
		self.cipherlist = []
		self.noncelist = []
		self.maskedlist = [] # collecting yu
		# For round 4
		self.shares_s_sk = self.create_2D_list(self.MAX_USER, self.MAX_USER)
		self.shares_bu = self.create_2D_list(self.MAX_USER, self.MAX_USER)


	def aggregation_input(self, z):
		self.z = z
		# xu is in Z^m_R
	
	def create_2D_list(self, r, c):
		a = [0] * c 
		for i in range(c):
			a[i] = [None] * r
		return a

	def round0_keys_server_collect(self, user_id, c_pk, s_pk):
		# Input:
		# user_id: the integer that denotes the user's ID
		# c_pk: secret key from user u
		# s_pk: public key from user u
		self.keylist.append((user_id, c_pk, s_pk))
		self.u1.add(user_id)
		if self.debug == True:
			print('server round 0: collected user id: {}, c_pk: {}, s_pk: {}'.format(user_id, c_pk, s_pk))

	def round0_keys_server_broadcast(self, user):
		# Input:
		# user: a class that receive the broadcast message 
		# call this when the collection is done from u2
		assert(len(self.keylist) > self.t-1)
		if self.debug:
			print('DEBUG: round0_keys_server_broadcast, keylist length: {}'.format(len(self.keylist)))
		for (u, c, s) in self.keylist: 
			if user.user_id == u:
				user.round1_keys_user_receive(self.keylist)

	def round1_cipher_server_collect(self, user_id, e, nonce):
		# Input:
		# user_id: the integer that denotes the user's ID
		# e: 1D ciphertext array from user (user_id)
		self.cipherlist.append((user_id, e))
		self.noncelist.append((user_id, nonce))
		self.u2.add(user_id)
				
	def round1_cipher_server_broadcast(self, user):
		# Input:
		# user: a class that receive the broadcast message 
		# call this when the collection is done from u2  
		# if self.debug:
		# 	print('DEBUG: current length of cipherlist: {}, t: {}'.format(len(self.cipherlist), self.t))
		
		assert(len(self.cipherlist) > self.t-1)
		for (u, e) in self.cipherlist: 
			if user.user_id == u:
				# This is necessary since some users might not generate e correctly in round 1.
				# for v in len(e):
				# 	if v in self.u2 == False:
				# 		e[v] = 0 
				user.round2_cipher_user_receive(self.cipherlist, self.noncelist)


	def round2_masked_server_collect(self, user_id, yu):
		# Input:
		# user_id: the integer that denotes the user's ID
		# yu: 1D masked input vector from user (user_id) 
		self.maskedlist.append(yu)
		self.u3.add(user_id)
	
	def round2_masked_server_broadcast(self, user):
		# Input:
		# user: a class that receive the broadcast message 
		# call this when the collection is done from u3, it will broad cast the set u3 to every other user
		assert(len(self.maskedlist) > self.t-1)
		for u in self.u3: 
			if user.user_id == u:
				user.round3_masked_user_receive(self.u3)
				
	def round3_u4_server_broadcast(self, user):
		# Input:
		# user: a class that receive the broadcast message 
		# call this when the collection is done from u6, it will broad cast the set u6 to every other user
		# Since we don't implement round3, here the u4 is same as u3
		self.u4 = self.u3
		assert(len(self.u4) > self.t-1) 
		for u in self.u4: 
			if user.user_id == u:
				user.round4_user_receive_and_broadcast(self, self.u4)

	def round4_server_collect_s(self, s_vu, v, u):
		# Input:
		# s_vu: the secret shares for users v ∈ U2\U3, 
		self.u5.add(u)
		self.shares_s_sk[v][u] = s_vu
		if self.debug:
			if self.debug_level == 2:
				print('Current shares_sk: {}'.format(self.shares_s_sk))

	def round4_server_collect_b(self, b_vu, v, u):
		# Input:
		# b_vu: the secret shares for users v ∈ U3, 
		self.u5.add(u)
		self.shares_bu[v][u] = b_vu
		if self.debug:
			if self.debug_level == 2:
				print('Current shares_bu: {}'.format(self.shares_bu))

	def round4_server_collect_shares(self, b_v, s_v, v):
		# Input:
		# b_vu: the secret shares for users v ∈ U3, 
		self.shares_bv = b_v
		self.shares_s = s_v

	def round4_shares_server_reconstruct(self):
		sum_pu = np.zeros(self.z.shape, dtype = int)
		sum_p_uv = np.zeros(self.z.shape, dtype = int)

		assert(len(self.u5) > self.t-1) 
		for u in self.u2:

			if (u in self.u3):
				print('u {} is in u3'.format(u))
				# For each user u ∈ U3, 
				# reconstruct bu← SS.recon({bu,v}v∈U5, t) 
				# and then recompute pu using the PRG.
				bu = Shamir.combine(list(filter(None, self.shares_bu[u])), ssss = False)
				dhu = DiffieHellman(16)
				dhu.assign_private_key(int(hexlify(bu).decode(), 16))				
				np.random.seed(int(bu.hex(), base = 16) % 2**32)
				pu = np.random.randint(0, high = self.R, size = self.z.shape)	
				sum_pu += pu	
				
			else:
				print('u {} is in u2 minus u3'.format(u))
				# For each user in u ∈ U2\ U3, reconstruct sSK u ← SS.recon({sSK u,v}v∈U5, t) 
				# and use it (together with the public keys received in the AdvertiseKeys round) 
				# to recompute pv,u for all v ∈ U3 using the PRG.
				assert (len(self.u2) - len(self.u3) > self.t - 1)

				if self.debug:
					print('DEBUG: Shamir.combine: {}, ({}) '.format(self.shares_s_sk[u],u))
					print('DEBUG: Shamir.combine: {}, ({}) '.format(list(filter(None, self.shares_s_sk[u])),u))
				su_sk = Shamir.combine(list(filter(None, self.shares_s_sk[u])), ssss = False)
				dhu = DiffieHellman(16)
				dhu.assign_private_key(int(hexlify(su_sk).decode(), 16))

				for v in self.u3:
					# Retrieve sv_pk from keylist
					sv_pk = [keylist_item[2] for keylist_item in self.keylist if keylist_item[0] == v][0]
					s_uv = dhu.gen_shared_key(sv_pk).encode() 
					if self.debug:
						print('DEBUG: ({},{}) su_sk: {}, sv_pk: {}, s = {}'.format(u,v,dhu.get_private_key(), sv_pk, s_uv))
					np.random.seed(int(s_uv.hex()) % 2**32)
					rand_vector = np.random.randint(0, high = self.R,size = self.z.shape)
					if u > v:
						sum_p_uv += rand_vector
					elif (u == v):
						sum_p_uv += 0
					else:
						sum_p_uv += -rand_vector
		self.z = (sum(self.maskedlist) - sum_pu + sum_p_uv)  % self.R 
		if self.debug:
		 	print('DEBUG: z: {}'.format(self.z))


class secure_aggregation_user:
	def __init__(self, t, user_id, m = 1, R = 31, active_adversary_mode = False):
		self.user_id = user_id
		self.R = R # Field from which
		self.m = m
		self.user_id = user_id
		self.u2 = set()
		self.mode = AES.MODE_GCM
		self.active_adversary_mode = active_adversary_mode
		self.t = t
		self.MAX_USER = 1000
		self.cipherlist_r2 = []
		self.noncelist_r2 = []
		self.debug = True
		self.debug_level = 1
		self.nonce = [None] * self.MAX_USER

	
	def user_input(self, xu):
		assert(max(xu) < self.R, "Input invalid, may overflow")
		self.xu = xu
		self.m = xu.shape
		# xu is in Z^m_R


	def round0_keys_user_generate(self):
		# Generate key pairs (c_pk, c_sk) and (s_pk, s_sk)
		d1 = DiffieHellman(16) 
		d2 = DiffieHellman(16) 
		self.dh1 = d1
		self.dh2 = d2
		self.c_pk = d1.gen_public_key()  # Type: int. 512 Hex
		self.c_sk = d1.get_private_key() 
		self.s_pk = d2.gen_public_key() 
		self.s_sk = d2.get_private_key()


	def round0_keys_user_send(self, server):
		# Input:	
		# server: the server that the user is communicating with
		# Send (c_pk || s_pk || sigma) to server through private authenticated channel 
		server.round0_keys_server_collect(self.user_id, self.c_pk, self.s_pk)


	def round1_keys_user_receive(self, keylist):
		# Input:
		# keylist: a list of (user_id, c_pk, s_pk) 

		# A user's function that receive keylist from server 
		# and generate the ciphertext of shared private key paris e_uv
		# store the value of keylist
		self.keylist_r1 = keylist
		u1_len = len(keylist)
		# create a list of e_uv, since u is fixed for the user, so e is an 1D array
		# self.e[v] is the ciphertext e_uv
		self.e = [None] * self.MAX_USER
		assert(u1_len > self.t - 1)
		cv_pk = [x[1:] for x in keylist]
		assert(len(cv_pk) == len(list(set(cv_pk)))) 
		# check for duplication
		# sample a random element bu from field F to be used as a seed for a PRG
		# field F's length l need to be larger than 2^k 
		self.bu = random_bytes(16) 
		# e.g. b'\xf5:\xa6\xca\xf5\xa5\x0eO\xc0\x9b\xc6G\xc1\xedV\x1c'

		#generate shares of suv_sk
		tmp = '{:0>32x}'.format(self.s_sk)
		self.s_sk  = unhexlify(tmp.encode()) # Overwrite with the correct format
		self.shares_s_sk = Shamir.split(self.t, len(keylist), self.s_sk, ssss=False)
		if self.debug:
			print('DEBUG: Shamir.split: {}, ({}) '.format(self.shares_s_sk,self.user_id))

		#generate shares of bu
		self.shares_bu = Shamir.split(self.t, len(keylist), self.bu, ssss=False)

		#For each other user v ∈ U1\ {u}, 
		#compute eu,v ← AE.enc(KA.agree(cSK u , cP K v ), u||v||sSK u,v||bu,v)
		idx = 0
		for (v, cv_pk, sv_pk) in keylist:
			if (v != self.user_id): 
				private_shared_key = self.dh1.gen_shared_key(cv_pk) 
				# if self.debug:
				# 	print('DEBUG: private_shared_key 1 between {}, {}: {}'.format(self.user_id, v, private_shared_key))
				# Note: private_shared_key is a hex string of length 64, (64*4 = 256B)
				mode = AES.MODE_GCM 
				encrypter, self.nonce[v] = create_AES_encrypter(unhexlify(private_shared_key), mode)
				# if self.debug:
				# 	print('DEBUG round1_keys_user_receive: share: v {}'.format(v))	
				# 	print('DEBUG round1_keys_user_receive: length of shares_bu: {}'.format(len(self.shares_bu)))	
				plaintext = (str(self.user_id) + ' ' +  \
							str(v) + ' ' + \
							str(self.shares_s_sk[idx][0]) + ' ' + \
							str(int(hexlify(self.shares_s_sk[idx][1]).decode('latin-1'),16)) + ' ' + \
							str(self.shares_bu[idx][0]) + ' ' + \
							str(int(hexlify(self.shares_bu[idx][1]).decode('latin-1'),16)))

				ciphertext, tag  = encrypt(encrypter, plaintext.encode('utf-8'))
				if self.debug:
					if self.debug_level == 2:
						print('HEY! I am user {} (u), for user {} (v), the plaintext is {}'.format(self.user_id, v, plaintext.encode()))
						print('HEY! I am user {} (u), for user {} (v), the nonce is {}'.format(self.user_id, v, self.nonce[v]))								
				# update the e_uv
				self.e[v] = ciphertext
				if self.debug:
					if self.debug_level == 2:
						print('HEY! I am user {} (u), for user {} (v), the eu,v is {}'.format(self.user_id, v, ciphertext))
				idx += 1
		

	def round1_cipher_user_send(self, server):
		server.round1_cipher_server_collect(self.user_id, self.e, self.nonce)


	def round2_cipher_user_receive(self, cipherlist, noncelist):
		# A function that receive cipherlist from server 
		# and generate the ciphertext of shared private key paris e_uv
		# store the value of keylist
		
		self.cipherlist_r2 = cipherlist
		self.noncelist_r2 = noncelist
		for (v, e) in cipherlist:
			# if e[v] != None:
			self.u2.add(v)
		if self.debug:
			print('DEBUG round2_cipher_user_receive: Current length of u2 {}'.format(len(self.u2)))
		assert(len(self.u2) > self.t - 1)

		# For each other user v ∈ U2\ {u}, 
		# compute su,v ← KA.agree(sSK u , sP K v ) 
		# and expand this value using a PRG 
		# into a random vector pu,v = Δu,v· PRG(su,v), 
		sum_p_uv = np.zeros(self.xu.shape, dtype = int)
		idx_p_uv = 0
		p_uv = np.zeros(self.xu.shape, dtype = int)
		for (v, cv_pk, sv_pk) in self.keylist_r1:
			if (v in self.u2) and (v != self.user_id):
				s_uv = self.dh2.gen_shared_key(sv_pk).encode() 
				if self.debug:
					print('DEBUG 1: ({},{}) su_sk: {}, sv_pk: {}, s = {}'.format(self.user_id,v,self.dh2.get_private_key(), sv_pk, s_uv))
				np.random.seed(int(s_uv.hex()) % 2**32)
				rand_vector = np.random.randint(0, high = self.R,size = self.xu.shape)
				if (self.user_id > v):
					sum_p_uv += rand_vector
				elif (self.user_id == v):
					sum_p_uv += 0
				else:
					sum_p_uv -= rand_vector
		
		# Compute the user’s own private mask vector pu= PRG(bu). 
		# Then, Compute the masked input vector 
		# yu← xu+ pu+ sum_puv (mod R)
		np.random.seed(int(self.bu.hex(), base = 16) % 2**32)
		pu = np.random.randint(0, high = self.R, size = self.xu.shape)
		# pu = aes_random(self.bu.encode())
		yu = (self.xu + pu + sum_p_uv) % self.R 
		self.yu = yu
		if self.debug:
			if self.debug_level == 1:
				print('DEBUG round2_cipher_user_receive: user( {}) sum_p_uv, pu, {}, {}'.format(self.user_id, sum_p_uv, pu))
				print('DEBUG xu, yu {}, {}'.format(self.xu, self.yu))


	def round2_masked_user_send(self, server):
		server.round2_masked_server_collect(self.user_id, self.yu)
	

	def round3_masked_user_receive(self, u3):
		self.u3 = u3
	

	def round4_user_receive_and_broadcast(self, server, u4):
		self.u4 = u4
		assert(len(u4) > self.t - 1)
		# For each other user v ∈ U2\ {u}, 
		# decrypt the ciphertext v'||u'||s||b ← AE.dec(KA.agree(cSK u , cP K v ), e_vu )
		# received in the MaskedInputCollection round and assert that u = u′∧ v = v′.
		# Restore the nonce for v
		for (v, e_vu) in self.cipherlist_r2:
			if (v != self.user_id) and (v in self.u2):
				s_v = [] # a list of shares. 
				# Optimization: If we have collected more than t, then we can send
				b_v = []
				cv_pk = [keylist_r1_item[1] for keylist_r1_item in self.keylist_r1 if keylist_r1_item[0] == v][0]
				private_shared_key = self.dh1.gen_shared_key(cv_pk)
		# 		if self.debug:
		# 			print('DEBUG: private_shared_key 2 between {}, {}: {}'.format(self.user_id, v, private_shared_key))
				my_nonce = [nonceitem[1] for nonceitem in self.noncelist_r2 if nonceitem[0] == v][0]
				decrypter = create_AES_decrypter(unhexlify(private_shared_key), self.mode, my_nonce[self.user_id]) 
				plaintext = decrypt(decrypter, e_vu[self.user_id]).decode()
				plaintext_split = plaintext.split()
				v_prime = int(plaintext_split[0])
				u_prime = int(plaintext_split[1])
				s_vu_idx = int(plaintext_split[2])
				s_vu_share = int(plaintext_split[3])
				b_vu_idx = int(plaintext_split[4])
				b_vu_share = int(plaintext_split[5])
				assert(v_prime == v)
				assert(u_prime == self.user_id)	
				s_vu = (s_vu_idx, unhexlify(('{:0>32x}'.format(s_vu_share)).encode("latin-1")))
				b_vu = (b_vu_idx, unhexlify(('{:0>32x}'.format(b_vu_share)).encode("latin-1")))
				if v in self.u3:
					b_v.append(b_vu) # b_v is a list of b_vu that has u fixed as self.user_id
				else:
					s_v.append(s_vu) # s_v is a list of s_vu that has u fixed as self.user_id
				self.round4_u4_user_send(server, s_vu, b_vu, v, self.user_id)
				if self.debug:
					if self.debug_level == 2:
						print('DEBUG. HEY! plaintext is {}'.format(plaintext))
						print('DEBUG: ciphertext e_vu between {}, {}: {}'.format(v, self.user_id, e_vu[self.user_id]))
						print('DEBUG: nonce between {}, {}: {}'.format(v, self.user_id, my_nonce[self.user_id]))
				# self.round4_user_send_shares(server, b_v, s_v, v)


	def round4_u4_user_send(self, server, s_vu, b_vu, v, u):
		# Send a list of shares to the server, 
		# which consists of sSK v,ufor users v ∈ U2\ U3 and bv,u for users in v ∈ U3.
		if (v in self.u3):
			server.round4_server_collect_b(b_vu, v, u)
		else:
			server.round4_server_collect_s(s_vu, v, u)


	def round4_user_send_shares(self, server, s_v, b_v, v):
		# Send a list of shares to the server, 
		# which consists of sSK v,ufor users v ∈ U2\ U3 and bv,u for users in v ∈ U3.
		server.round4_server_collect_shares(b_v, s_v, v)





	