#!/usr/bin/env python
# -*- coding: utf-8 -*-

##	@file 		DiffieHellman.py
#	@brief 		Método de criptografia para troca de chaves 
#	@details 	Responsável pelo cálculo para troca de chaves entre usuários utilizando o método Diffie-Hellman
#	@since		09/09/2016
#	@date		30/09/2016
#	@authors	David e Genilson
#	@copyright	2016 - All rights reserveds
#	@sa 		http://projetos.imd.ufrn.br/davidcardoso-ti/imd0703/blob/master/chat_criptografado/DiffieHellman.py


class DiffieHellman(object):
	global PRIMO, ALFA, My_PVT, My_PUB, Other_PUB, KEY_SESSION

	## 	@brief Método construtor
	#   @details Inicializa váriaveis
	#   @param p 		- Número primo
	#   @param a 		- Alfa é raiz primitiva do número primo
	#   @param pvt 		- chave privada
	def __init__(self, p=1021, a=7, pvt=97):
		self.PRIMO 			= int(p)
		self.ALFA 			= int(a)
		self.My_PVT 		= int(pvt)
		self.My_PUB 		= self.calcPub(self.My_PVT)
		self.Other_PUB 		= self.My_PUB
		self.KEY_SESSION  	= self.calcKeySession(self.My_PVT, self.Other_PUB)

	## 	@brief Método calcPub()
	#   @details Calcula a chave pública
	#   @param pvt 	- Chave privada
	#   @return 	  Chave pública
	def calcPub(self, pvt):
		return (self.ALFA ** pvt) % self.PRIMO

	## 	@brief Método calcKeySession()
	#   @details Calcula a chave secreta da sessão
	#   @param pvt - Chave privada de um usuário 'A'
	#   @param pub - Chave pública de um usuário 'B'
	#   @return      Chave secreta da sessão
	def calcKeySession(self, pvt, pub):
		if pvt < self.PRIMO:
			return (pub ** pvt) % self.PRIMO
		else:
			print "Erro: Chave privada tem que ser menor que PRIMO!"
			new_pvt = raw_input("Digite a nova chave privada < que %s: " % (self.PRIMO))
			self.calcKeySession(new_pvt, pub)

	## 	@brief Método setPrimo()
	#   @details Altera o número PRIMO
	#   @param p - novo número primo
	def setPrimo(self, p):
		if int(p) > self.ALFA and int(p) > self.My_PVT:
			self.PRIMO  = int(p)
			self.My_PUB = self.calcPub(self.My_PVT)
			return "Número PRIMO alterado com sucesso! (%s, %s)" % ('xxx', self.My_PUB)
		else:
			return "Erro: Número PRIMO tem que ser maior que ALFA!"
			new_primo = raw_input("Digite o novo primo > que %s: " % (self.ALFA))
			self.setPrimo(new_primo)

	## 	@brief Método setAlfa()
	#   @details Altera o ALFA para uma outra raiz primitiva de PRIMO
	#   @param a - novo alfa
	def setAlfa(self, a):
		if int(a) < self.PRIMO: # pendente criticar se o novo ALFA é realmente raiz primitiva de PRIMO
			self.ALFA   = int(a)
			self.My_PUB = self.calcPub(self.My_PVT)
			return "Número ALFA alterado com sucesso!"
		else:
			return "Erro: Número ALFA tem que ser menor que PRIMO!"
			new_alfa = raw_input("Digite o novo alfa < que %s: " % (self.PRIMO))
			self.setAlfa(new_alfa)

# TESTE PARA GERAR CHAVE SECRETA DE SESSÃO ASSOCIATIVA DE ACORDO COM A QTD DE PARTICIPANTES
# como o chat é em broadcast, esse tipo de tratamento não é simples
# portanto, deixamos o chat funcionando corretamente com vários participantes sem mudar a chave
# ou apenas com um cliente controlando a mudança de chaves via Diffie-Hellman
if __name__ == '__main__':
	dh_a = DiffieHellman(1021, 7, 321)
	dh_b = DiffieHellman(1021, 7, 123)
	dh_c = DiffieHellman(1021, 7, 97)

	# A envia sua chave publica para B
	# B gera chave parcial A+B
	dh_b.Other_PUB 		= dh_b.calcKeySession(dh_b.My_PVT, dh_a.My_PUB)

	# C gera chave secreta de sessão A+B+C
	dh_c.KEY_SESSION 	= dh_c.calcKeySession(dh_c.My_PVT, dh_b.Other_PUB)

	# B envia sua chave publica para C
	# C gera chave parcial B+C
	dh_c.Other_PUB 	 	= dh_c.calcKeySession(dh_c.My_PVT, dh_b.My_PUB)

	# A gera chave secreta de sessão A+B+C
	dh_a.KEY_SESSION 	= dh_a.calcKeySession(dh_a.My_PVT, dh_c.Other_PUB)

	# C envia sua chave publica para A
	# A gera chave parcial A+C
	dh_a.Other_PUB 		= dh_a.calcKeySession(dh_a.My_PVT, dh_c.My_PUB)

	# B gera chave secreta de sessão A+B+C
	dh_b.KEY_SESSION 	= dh_b.calcKeySession(dh_b.My_PVT, dh_a.Other_PUB)


	print "[Usuário A] Chaves PVT/PUB (%s, %s) ==> Chave secreta da sessão (%s) " % (dh_a.My_PVT, dh_a.My_PUB, dh_a.KEY_SESSION)
	print "[Usuário B] Chaves PVT/PUB (%s, %s) ==> Chave secreta da sessão (%s) " % (dh_b.My_PVT, dh_b.My_PUB, dh_b.KEY_SESSION)
	print "[Usuário C] Chaves PVT/PUB (%s, %s) ==> Chave secreta da sessão (%s) " % (dh_c.My_PVT, dh_c.My_PUB, dh_c.KEY_SESSION)

