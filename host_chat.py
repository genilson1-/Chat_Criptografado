#!/usr/bin/env python
# -*- coding: utf-8 -*-

##	@file 		host_chat.py
#	@brief 		Host de Chat via TCP/IP
#	@details 	Responsável por manter a conexão entre os clientes através de sockets via protocolo TCP/IP
#	@since		09/09/2016
#	@date		30/09/2016
#	@authors	David e Genilson
#	@copyright	2016 - All rights reserveds
#	@sa 		http://projetos.imd.ufrn.br/davidcardoso-ti/imd0703/blob/master/chat_criptografado/host_chat.py

import os, sys		# os, sys 	- recursos de sistema
import socket		# socket 	- usada para criar e gerenciar sockets
import select		# select 	- usada fazer o controle de eventos das conexões via poll()
import Queue		# Queue 	- usada para gerenciamento de filas
import threading	# threading - usada para gerenciamento multi-thread

# Variáveis
message_queues  = {}        		#< message_queues 	- fila de mensagens a serem enviadas
TIMEOUT_E       = 500     			#< TIMEOUT_E 		- tempo de espera para o evento (milisegundos)
TIMEOUT_T       = 1.0       		#< TIMEOUT_T 		- tempo de espera para o Thread (segundos)
SUCESS          = 'Ok!'     		#< SUCESS 			- mensagem de recebido com sucesso
FAILURE         = 'Closed!' 		#< FAILURE 			- mensagem de conexão fechada
ENDL            = '\n'      		#< ENDL 			- quebra linha

NOTIFY_DH 		= '[PUBKEY]'		#< NOTIFY_DH 		- prefixo para notificar outros clientes da mudança de chave pública
GET_PUBKEY 		= '[ENTRAR]'		#< GET_PUBKEY 		- string reservada para solicitar chave pública
ALTER_PRIMO		= '[TROCARPRIMO]'	#< ALTER_PRIMO		- string reservada para alterar o PRIMO da classe DiffieHellman
ALTER_ALFA		= '[TROCARALFA]'	#< ALTER_ALFA		- string reservada para alterar o ALFA da classe DiffieHellman

# Flags comumente usadas para controle de eventos com o método select.poll()
READ_ONLY 		= select.POLLIN | select.POLLPRI | select.POLLHUP | select.POLLERR
READ_WRITE 		= READ_ONLY 	| select.POLLOUT

# Validação dos argumentos passados via linha de comando
if sys.argv.__len__() == 3:
	host_ip 	= str(sys.argv[1]) 		#< host_ip 		- IP do servidor
	host_port 	= int(sys.argv[2]) 		#< host_port 	- Porta do servidor
else:
	print 'Argumentos via linha de comando divergentes. Finalizando...'
	sys.exit()

try:
	host_ip = socket.gethostbyname(host_ip)
except socket.gaierror:
	print 'Nome do host não pode ser resolvido. Finalizando...'
	sys.exit()


## @brief Função para limpar console
def clearConsole():
	os.system('cls' if os.name == 'nt' else 'reset')


## 	@brief Função que manda um feedback ao cliente
# 	@details Usado pelo método run() da classe threading
# 	@param client_socket - socket cliente
# 	@param msg           - mensagem de feedback a ser enviada ao cliente 
def feedbackClient(client_socket, msg):
	client_socket.send(msg)


## 	@brief Função que manda uma mensagem ao cliente
# 	@details Usado pelo método run() da classe threading
# 	@param client_socket - socket cliente
# 	@param msg           - mensagem a ser enviada em broadcast aos clientes
def broadcastClient(client_socket, msg):
	try:
		client_socket.send(msg)
	except:
		print '(      Servidor     ) Erro ao tentar enviar mensagem ao cliente! %s' % ENDL


## 	@brief Função para tratamento multi-thread
# 	@details Usada para chamar as funções feedbackClient e broadcastClient
# 	@param func              - função a ser chamada
# 	@param client_socket     - socket cliente
# 	@param msg               - mensagem a ser enviada
def handlerThread(func, client_socket, msg):
	handler = threading.Thread(target=func, args=(client_socket, msg))
	handler.daemon = True    # daemon Thread finaliza junto com o programa principal
	handler.start()          # inicia o Thread
	handler.join(TIMEOUT_T)  # aguarda o Thread ser processado
	handler.isAlive()        # verifica o status do Thread, caso esteja ativo, executa o TIMEOUT_T


# Endereço do servidor
server_address = (host_ip, host_port)  #< server_address - Endereço do servidor

# Cria socket TCP/IP
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  #< sock - server socket TCP/IP
sock.setblocking(0)

# Vincula o socket ao endereço do servidor
sock.bind(server_address)

# Habilita modo de escuta
sock.listen(5)

# Inicializa o poll de eventos
poller = select.poll()                  #< poller - controle dos sockets via eventos
poller.register(sock, READ_ONLY)

fd_to_socket = {sock.fileno(): sock, }  #< fd_to_socket - File descriptors de objetos socket

# limpa console
clearConsole()

print "=> Chat via TCP/IP | Servidor"
print "   By David e Genilson"
print "   Enjoy it! xD %s%s" % (ENDL, ENDL)

print '   Servidor ativo: %s porta %s %s%s' % (host_ip, host_port, ENDL, ENDL)

print '[Aguardando eventos...] %s' % (ENDL)

# Loop principal do servidor/host
while True:

	# Aguarda algum socket estar pronto para ser processado (espera TIMEOUT_E milisegundos)
	events = poller.poll(TIMEOUT_E)

	# Verifica e age de acordo com o tipo de evento de cada socket
	for fd, flag in events:

		# Resgatando o socket atual do file descriptor
		s = fd_to_socket[fd]

		# Eventos de entrada
		if flag & (select.POLLIN | select.POLLPRI):

			if s is sock:
				# Socket servidor está pronto para aceitar uma conexão
				connection, client_address = s.accept()
				connection.setblocking(0)

				print '%s Conexão aceita! %s' % (str(client_address), ENDL)
				print '[Aguardando eventos...] %s' % (ENDL)

				# Adiciona conexão ao file descriptor e ao poll de eventos
				poller.register(connection, READ_ONLY)
				fd_to_socket[connection.fileno()] = connection

				# Cria uma fila para a nova conexão para armazenar mensagens a serem enviadas
				message_queues[connection] = Queue.Queue()

				# Salva a nova conexão/socket do cliente no file descriptor
				fd_to_socket.update({connection.fileno(): connection})

			else:
				data = s.recv(1024)
				if data:
					# Cliente enviou alguma mensagem
					#print '%s Recebido: "%s". %s' % (str(s.getpeername()), data, ENDL)

					if data != 'sair':
						# Mofifica canal para modo escrita/resposta
						poller.modify(s, READ_WRITE)
						# Adiciona mensagem à fila de mensagens do canal
						message_queues[s].put(data)
					else:
						# Cliente fechou conexão - Hung Up
						print '%s Fechando após receber Hang Up. %s' % (str(s.getpeername()), ENDL)

						# Envia feedback negativo ao cliente
						# Tratamento multi-thread | funcao, conexão, mensagem
						handlerThread(feedbackClient, s, FAILURE)

						print '[Aguardando eventos...] %s' % (ENDL)

						# Mofifica canal para modo escrita/resposta
						poller.modify(s, select.POLLERR)

						# Remove a fila de mensagens da conexão
						del message_queues[s]

						# Para de escutar conexão
						poller.unregister(s)
						del fd_to_socket[s.fileno()]
						s.close()

		# Socket está pronto para enviar dados, se houver algum dado na fila
		elif flag & select.POLLOUT:
			try:
				next_msg = message_queues[s].get_nowait() # retira msg da fila
			except Queue.Empty:
				# Sem mensagens na fila, remove cliente da lista de outputs/writable
				print '%s Fila de mensagens está vazia. %s' % (str(s.getpeername()), ENDL)
				print '[Aguardando eventos...] %s' % (ENDL)
				poller.modify(s, READ_ONLY)
			else:
				# Enviar feedback positivo ao cliente
				# Tratamento multi-thread | funcao, conexão, mensagem
				if next_msg[:len(NOTIFY_DH)] != NOTIFY_DH and next_msg[:len(GET_PUBKEY)] != GET_PUBKEY and next_msg[:len(ALTER_PRIMO)] != ALTER_PRIMO and next_msg[:len(ALTER_ALFA)] != ALTER_ALFA:
					handlerThread(feedbackClient, s, SUCESS)

				# Tratamento para enviar msg em Broadcast 
				count = 0
				for index, client in fd_to_socket.iteritems():
					# se não é o socket servidor e o cliente que enviou a msg
					if client is not sock and client is not s: 
						# Prepara mensagem a ser enviada ao cliente
						broadcast_msg = str(ENDL) + str(s.getpeername()) 	# prefixo: quebra de linha + IP/Porta de quem enviou a msg
						broadcast_msg = broadcast_msg.ljust(28 , ' ')		# prefixo: à esquerda com padding de 28 posições
						broadcast_msg += str(next_msg) 						# prefixo + msg
						# Tratamento multi-thread | funcao, conexão, mensagem
						handlerThread(broadcastClient, client, broadcast_msg)
						count += 1
						# Se algum cliente solicitou chave pública
						# envia pedido apenas para 1 cliente que já está no chat
						if next_msg == GET_PUBKEY and count == 1:
							break
				print "(      Servidor     ) Broadcast para %i cliente(s)! %s" % (count, ENDL)

		# Erro de conexão com o socket
		elif flag & select.POLLERR:
			print '%s Fechando... %s' % (str(s.getpeername()), ENDL)
			# Enviar mensagem ao cliente
			# Tratamento multi-thread | funcao, conexão, mensagem
			handlerThread(feedbackClient, s, FAILURE)

			print '[Aguardando conexões...] %s' % (ENDL)

			# Remove a fila de mensagens da conexão
			del message_queues[s]

			# Para de escutar a conexão
			poller.unregister(s)
			del fd_to_socket[s.fileno()]
			s.close()
