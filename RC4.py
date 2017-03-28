#!/usr/bin/env python
# -*- coding: utf-8 -*-

##	@file 		RC4.py
#	@brief 		Criptossistema de encriptação e decriptação RC4
#	@details 	Responsável pela criptografia das mensagens enviadas no chat
#	@since		09/09/2016
#	@date		30/09/2016
#	@authors	David e Genilson
#	@copyright	2016 - All rights reserveds
#	@sa 		http://projetos.imd.ufrn.br/davidcardoso-ti/imd0703/blob/master/chat_criptografado/RC4.py


import sys # sys - recursos de sistema

class RC4(object):
	global S
	S = []

	def __init__(self, PASS_RC4='160'):
		self.key = PASS_RC4

	## 	@brief Função ksa()
	#   @details  Usada para inicializar a permutação no array S. K.Length é definido como o número de bytes na chave e pode variar entre 1 e 256
	def ksa(self):
		j = 0
		if (type(self.key) == str):
			key_int = self.charToInt(self.key)
		tamanho_chave = len(key_int)
		global S
		S = range(256)
		for x in range(256):
			j = (j + S[x] + key_int[x % tamanho_chave]) % 256
			S[x], S[j] = S[j], S[x]

	## 	@brief Função prga()
	#   @details O PRGA modifica o estado e a saída do byte resultante. Em cada repetição
	#   @param msg      - Mensagem a ser criptografada
	#	@return result	- Retorna a msg criptografada
	def prga(self, msg):
		i = 0
		j = 0
		if (type(msg) == str):
			msg = self.charToInt(msg)

		tamanho_msg = len(msg)
		result = []
		for x in range(tamanho_msg):
			i = (i + 1) % 256
			j = (j + S[i]) % 256
			S[i], S[j] = S[j], S[i]
			result.append(S[(S[i] + S[j]) % 256] ^ msg[x])
		return (result)

	## 	@brief Função charToInt()
	#   @details Transforma a msg em uma lista de inteiros
	#   @param txt      - Texto a ser convertido
	#	@return result	- Texto convertido
	def charToInt(self, txt):
		result = []
		for index, value in enumerate(txt):
			result.append(ord(value))
		return (result)

	## 	@brief Função encrypt()
	#	@details Encripta a mensagem com RC4
	#	@param msg 		- Texto a ser encriptado
	#	@return resul 	- Mensagem encriptada
	def encrypt(self, msg):
		x = self.ksa()
		result = self.prga(msg)
		text = []
		for index, value in enumerate(result):
			text += chr(value)
		result = ''.join(text)
		return (result)

	## 	@brief Função decrypt()
	#	@details Decripta a mensagem com RC4
	#	@param msg 		- Texto a ser decriptado
	#	@return resul 	- Mensagem decriptada

	def decrypt(self, msg):
		x = self.ksa()
		result = self.prga(msg)
		text = []
		for index, value in enumerate(result):
			text += chr(value)
		result = ''.join(text)
		return (result)
