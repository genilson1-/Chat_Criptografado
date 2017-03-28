#!/usr/bin/env python
# -*- coding: utf-8 -*-

##	@file 		client_chat.py
#	@brief 		Cliente de Chat via TCP/IP
#	@details 	Conecta com o host para enviar e receber mensagens
#	@since		09/09/2016
#	@date		30/09/2016
#	@authors	David e Genilson
#	@copyright	2016 - All rights reserveds
#	@sa 		http://projetos.imd.ufrn.br/davidcardoso-ti/imd0703/blob/master/chat_criptografado/client_chat.py

import os, sys  # os, sys 	- recursos de sistema
import socket  # socket 	- usada para criar e gerenciar sockets
import threading  # threading - usada para gerenciamento multi-thread
import time

from SDES import SDES  # SDES 			- classe do criptossistema SDES
from RC4 import RC4  # RC4 			- classe do criptossistema RC4
from DiffieHellman import DiffieHellman  # DiffieHellman	- classe do método Diffie-Hellman para troca de chaves

# Variáveis
TIMEOUT_S = 1.0  # < TIMEOUT_S 	- tempo de espera para o socket (segundos)
TIMEOUT_T = 1.0  # < TIMEOUT_T 	- tempo de espera para o Thread (segundos)
SUCESS = 'Ok!'  # < SUCESS 		- retorno de mensagem recebida com sucesso
FAILURE = 'Closed!'  # < FAILURE 		- retorno de conexão fechada
ENDL = '\n'  # < ENDL 		- quebra linha
DEBUG = False  # < DEBUG 		- modo DEBUG==True imprime na tela as chaves
BOLD = '\033[1m'  # < BOLD 		- negrito
GREEN = BOLD + '\033[32m'  # < GREEN 		- cor verde para destacar impressões no terminal
BLUE = BOLD + '\033[34m'  # < BLUE 		- cor azul para destacar impressões no terminal
WHITE = BOLD + '\033[37m'  # < WHITE 		- cor branca para destacar impressões no terminal
NORMAL = '\033[0;0m'  # < NORMAL 		- cor padrão para impressões no terminal


## Função para limpar console
def clearConsole():
    os.system('cls' if os.name == 'nt' else 'reset')


## 	@brief 	 Função formatPass()
#	@details Função pra formatar a chave digitada pelo usuário
#	@param 	 tmp 	- valor a ser validado e formatado
#	@param 	 c 		- tipo de criptossistema
#	@return  chave formatada ou a chave antiga, caso tmp seja inválido
def formatPass(tmp, c):
    global PASS_SDES, PASS_RC4

    # SDES
    if c == 's':
        try:
            if int(tmp) <= 1023:
                return str(bin(int(tmp)))[2:].rjust(10, '0')
            else:
                print "[SDES] Senha deve ser um inteiro de 0 até 1023!"
                return formatPass(160, c) if PASS_SDES == '' else PASS_SDES
        except:
            print "[SDES] Senha deve ser um inteiro de 0 até 1023!"
            return formatPass(160, c) if PASS_SDES == '' else PASS_SDES
    # RC4
    elif c == 'r':
        if len(str(tmp)) > 0:
            return str(tmp)
        else:
            print "[RC4] Senha deve ser um inteiro de 0 até 1023!"
            return '160' if PASS_RC4 == '' else PASS_RC4


# Segurança / Criptografia
CRIPT = 's'  # < CRIPT 			- flag para o tipo de criptossistema ('s' = SDES, 'r' = RC4)
ALTER_PASS_DH = '[TROCARPVTKEY]'  # < ALTER_PASS_DH 	- prefixo para troca de senha via Diffie-Hellaman
ALTER_PASS = '[TROCARSENHA]'  # < ALTER_PASS  		- prefixo para troca de senha
ALTER_CRIPT = '[TROCARCRIPT]'  # < ALTER_CRIPT 		- prefixo para troca de criptossistema
NOTIFY_DH = '[PUBKEY]'  # < NOTIFY_DH 		- prefixo para notificar outros clientes da mudança de chave pública
GET_PUBKEY = '[ENTRAR]'  # < GET_PUBKEY 		- string reservada para solicitar chave pública
ALTER_PRIMO = '[TROCARPRIMO]'  # < ALTER_PRIMO		- string reservada para alterar o PRIMO da classe DiffieHellman
ALTER_ALFA = '[TROCARALFA]'  # < ALTER_ALFA		- string reservada para alterar o ALFA da classe DiffieHellman
My_DH = DiffieHellman()
KEY_SESSION = My_DH.calcKeySession(My_DH.My_PVT, My_DH.My_PUB)  # 879
PASS_SDES = formatPass(KEY_SESSION, 's')
PASS_RC4 = formatPass(KEY_SESSION, 'r')


## 	@brief Função notifyDH()
#	@details Função para notificar aos outros clientes sobre a mudança de chave (envia chave pública)
#	@param sock 	- socket cliente
#	@param flag		- flag de controle (NOTIFY_DH, GET_PUBKEY, ALTER_PRIMO, ALTER_ALFA)
def notifyDH(sock, flag):
    global My_DH, NOTIFY_DH, GET_PUBKEY, ALTER_PRIMO, ALTER_ALFA

    if flag == NOTIFY_DH or flag == GET_PUBKEY:
        msg = NOTIFY_DH + str(My_DH.My_PUB)
        msg = str(msg)
        print "Enviando chave pública aos outros clientes!%s " % (ENDL)

    elif flag == ALTER_PRIMO:
        msg = flag + str(My_DH.PRIMO)
        msg = str(msg)
        print "Enviando número PRIMO aos outros clientes!%s " % (ENDL)

    elif flag == ALTER_ALFA:
        msg = flag + str(My_DH.ALFA)
        msg = str(msg)
        print "Enviando ALFA aos outros clientes!%s " % (ENDL)

    sock.sendall(msg)


## 	@brief Função alterMyKeyPair()
#	@details Função para alterar o par de chaves (privado, público)
#	@param sock	- socket cliente
#	@param msg 	- chave privada usada como base na mudança do par de chaves
#	@param flag - flag de controle
#	@return		True ou False
def alterMyKeyPair(sock, msg, flag):
    global My_DH
    try:
        msg = int(msg)
        if msg < My_DH.PRIMO and msg >= 2:
            My_DH.My_PVT = int(msg)
            My_DH.My_PUB = My_DH.calcPub(My_DH.My_PVT)
            clearConsole()
            print "Par de chaves atualizado com sucesso (xxx, %s)!%s" % (My_DH.My_PUB, ENDL)
            if flag == ALTER_PASS_DH:
                alterPass(sock, My_DH.Other_PUB, flag)
            notifyDH(sock, NOTIFY_DH)
            return True
        else:
            print "1. Chave privada deve ser um inteiro de 2 até %s! %s" % (My_DH.PRIMO - 1, ENDL)
            return False
    except:
        print "2. Chave privada deve ser um inteiro de 2 até %s! %s" % (My_DH.PRIMO - 1, ENDL)
        return False


## 	@brief Função alterPass()
#	@details Função para alterar a senha/chave secreta da sessão
#	@param sock - socket cliente
#	@param msg 	- senha ou chave pública de outro cliente
#	@param flag 	- troca de senha diretamente ou via DiffieHellman
def alterPass(sock, msg, flag):
    global DEBUG, ALTER_PASS, ALTER_PASS_DH, My_DH, KEY_SESSION, PASS_SDES, PASS_RC4
    try:
        # troca via DiffieHellman
        if flag == ALTER_PASS_DH:
            My_DH.Other_PUB = int(msg)
            if DEBUG:
                print "PVT %s OTHER_PUB %s %s" % (My_DH.My_PVT, My_DH.Other_PUB, ENDL)
            KEY_SESSION = My_DH.calcKeySession(My_DH.My_PVT, My_DH.Other_PUB)
        # troca direta
        elif flag == ALTER_PASS:
            KEY_SESSION = msg
        else:
            print "Método de troca de senha inválido! %s" % (ENDL)
            return;

        # SDES
        PASS_SDES = formatPass(KEY_SESSION, 's')
        if DEBUG:
            print "PASS_SDES : %s%s" % (PASS_SDES, ENDL)

        # RC4
        PASS_RC4 = formatPass(KEY_SESSION, 'r')
        if DEBUG:
            print "PASS_RC4  : %s%s" % (PASS_RC4, ENDL)

        print "Chave secreta da sessão atualizada com sucesso!%s" % (ENDL)
    except:
        print "Falha ao atualizar a senha/chave secreta da sessão com a chave pública externa: %s%s" % (ENDL, msg)


## 	@brief Função alterCript()
#	@details Função para alterar criptossistema utilizado na troca de mensagens (SDES ou RC4)
#	@param msg 	- mensagem usada como base na mudança de criptossistema
def alterCript(msg):
    global CRIPT
    # SDES
    if msg.lower() == 's':
        CRIPT = 's'
        print "CRIPT: SDES %s" % (ENDL)
    # RC4
    elif msg.lower() == 'r':
        CRIPT = 'r'
        print "CRIPT: RC4 %s" % (ENDL)


## 	@brief Função readInputSend()
#	@details Função para ler mensagem do usuário e enviar via socket ao host TCP/IP
#	@param sock 	- socket cliente
#	@param prompt 	- mensagem a ser mostrada ao usuário no console
def readInputSend(sock, prompt):
    global My_DH
    message = raw_input(prompt)

    # Desligar (Hung Up)
    if message.lower() == 'sair':
        print 'Desligando...'
        sock.sendall('sair')

    # Solicitar chave pública
    elif message == GET_PUBKEY:
        print 'Solicitando chave pública para entrar no chat...'
        sock.sendall(GET_PUBKEY)

    # Mudar senha via DiffieHellman
    elif message[:len(ALTER_PASS_DH)] == ALTER_PASS_DH:
        alterMyKeyPair(sock, message[len(ALTER_PASS_DH):], ALTER_PASS_DH)

    # Mudar senha diretamente
    elif message[:len(ALTER_PASS)] == ALTER_PASS:
        alterPass(sock, message[len(ALTER_PASS):], ALTER_PASS)

    # Mudar criptossistema
    elif message[:len(ALTER_CRIPT)] == ALTER_CRIPT:
        alterCript(message[len(ALTER_CRIPT):])

    # Mudar número PRIMO da classe DiffieHellman / atualiza KEYSESSION
    elif message[:len(ALTER_PRIMO)] == ALTER_PRIMO:
        retorno = My_DH.setPrimo(message[len(ALTER_PRIMO):])
        print "%s %s" % (retorno, ENDL)
        notifyDH(sock, ALTER_PRIMO)
        time.sleep(1)
        notifyDH(sock, NOTIFY_DH)

    # Mudar ALFA da classe DiffieHellman / atualiza My_DH.My_PUB
    elif message[:len(ALTER_ALFA)] == ALTER_ALFA:
        retorno = My_DH.setAlfa(message[len(ALTER_ALFA):])
        print "%s %s" % (retorno, ENDL)
        notifyDH(sock, ALTER_ALFA)
        time.sleep(1)
        notifyDH(sock, NOTIFY_DH)

    # Enviar mensagem
    elif len(message) > 0:
        print 'Enviando mensagem...'
        msg = str(cryptosystem.encrypt(message))
        print(msg)
        sock.sendall(msg)


## 	@brief Função para tratamento multi-thread
# 	@details Usada para chamar outras funções para serem executadas via Thread
# 	@param func 	- função a ser chamada
# 	@param timeout 	- tempo de expiração do Thread
#	@param sock 	- socket cliente
#	@param prompt 	- mensagem a ser mostrada ao usuário no console
def handlerThread(func, timeout, sock, prompt):
    handler = threading.Thread(target=func, args=(sock, prompt,))
    handler.daemon = True  # daemon Thread finaliza junto com o programa principal
    handler.start()  # inicia o Thread
    handler.join(timeout)  # aguarda o Thread ser processado
    handler.isAlive()  # verifica o status do Thread, caso esteja ativo, executa o timeout


# Validação dos argumentos passados via linha de comando
if sys.argv.__len__() == 3:
    host_ip = str(sys.argv[1])  # < host_ip 	 	- IP do servidor
    host_port = int(sys.argv[2])  # < host_port  	- Porta do servidor
    DEBUG = False
elif sys.argv.__len__() == 4:
    host_ip = str(sys.argv[1])  # < host_ip 		- IP do servidor
    host_port = int(sys.argv[2])  # < host_port  	- Porta do servidor
    DEBUG = True if str(sys.argv[3]).lower() == 'debug' else False
else:
    print 'Argumentos via linha de comando insuficientes. Finalizando... %s' % (ENDL)
    sys.exit()

try:
    host_ip = socket.gethostbyname(host_ip)
except socket.gaierror:
    print 'Nome do host não pôde ser resolvido. Finalizando... %s' % (ENDL)
    sys.exit()

# Cria um socket TCP/IP - forma rápida
server_address = (host_ip, host_port)  # < server_address 	- Endereço do servidor
sock = socket.create_connection(server_address)  # < sock 			- socket / conexão
sock.settimeout(TIMEOUT_S)

# Qtd de caracteres usados para identificar o prefixo dos outros clientes
# padrao + ip + porta
ID = 28
# print "ID %s" % ID

# limpa console
clearConsole()

print BLUE + "=> Chat via TCP/IP | Cliente"
print "   By David e Genilson"
print "   Enjoy it! xD %s %s%s" % (NORMAL, ENDL, ENDL)

print "   Conexão estabelecida com o servidor %s porta %s %s" % (
GREEN + host_ip + NORMAL, GREEN + str(host_port) + NORMAL, ENDL)
print "   Console atualiza a cada %s segundos. %s%s" % (GREEN + str(TIMEOUT_T + TIMEOUT_S) + NORMAL, ENDL, ENDL)

print "=> Comandos especiais:%s" % (ENDL)
print "   - Envie %s 			para solicitar a chave pública de outro cliente." % (GREEN + GET_PUBKEY + NORMAL)
print "   - Envie %s<s|r> 		para alterar o criptossistema." % (GREEN + ALTER_CRIPT + NORMAL)
print "   - Envie %s<chave> 	para alterar a chave privada." % (GREEN + ALTER_PASS_DH + NORMAL)
print "   - Envie %s<senha> 	para alterar a senha diretamente." % (GREEN + ALTER_PASS + NORMAL)
print "   - Envie %s<primo> 	para alterar o número primo do DiffieHellman." % (GREEN + ALTER_PRIMO + NORMAL)
print "   - Envie %s<alfa> 		para alterar o alfa do DiffieHellman." % (GREEN + ALTER_ALFA + NORMAL)
print "   - Envie %s 			para finalizar o programa. %s" % (GREEN + 'SAIR' + NORMAL, ENDL)

print "   - Obs.: s => SDES; r => RC4; chave => número inteiro.%s%s" % (ENDL, ENDL)

print "=> Para enviar mensagens, basta digitar e apertar a tecla ENTER.%s" % (ENDL)

# Loop principal do cliente
while True:

    # Seleciona o criptossistema
    cryptosystem = SDES(PASS_SDES) if CRIPT == 's' else RC4(PASS_RC4)

    try:
        # Lê mensagem digitada pelo usuário, trata e envia ao host (espera TIMEOUT_T segundos)
        prompt = ''
        handlerThread(readInputSend, TIMEOUT_T, sock, prompt)

        # Controla o recebimento de mensagens (aguarda TIMEOUT_S segundos)
        data = sock.recv(1024)
        if data and len(data) > 0:

            # Servidor recebeu a mensagem deste cliente com sucesso
            if data == SUCESS:
                print 'Feedback: %s %s' % (data, ENDL)

            # Servidor fechou conexão
            elif data == FAILURE:
                print 'Feedback: %s %s' % (data, ENDL)
                break

            # Servidor enviou alguma mensagem de outro cliente
            else:
                # Envia chave pública devido à solicitação de outro cliente
                if data[ID:] == GET_PUBKEY:
                    notifyDH(sock, GET_PUBKEY)

                # Atualiza chave secreta da sessão depois da solicitação da chave pública
                elif data[ID:][:len(NOTIFY_DH)] == NOTIFY_DH:
                    print '%sRecebido: %s %s' % (ENDL, (BLUE + str(data) + NORMAL), ENDL)
                    alterPass(sock, data[ID + len(NOTIFY_DH):], ALTER_PASS_DH)

                # Atualiza numero PRIMO
                elif data[ID:][:len(ALTER_PRIMO)] == ALTER_PRIMO:
                    retorno = My_DH.setPrimo(data[ID + len(ALTER_PRIMO):])
                    print "%s %s" % (retorno, ENDL)
                    time.sleep(1)
                    notifyDH(sock, NOTIFY_DH)

                # Atualiza ALFA
                elif data[ID:][:len(ALTER_ALFA)] == ALTER_ALFA:
                    retorno = My_DH.setAlfa(data[ID + len(ALTER_ALFA):])
                    print "%s %s" % (retorno, ENDL)
                    time.sleep(1)
                    notifyDH(sock, NOTIFY_DH)

                # Decifra e imprime mensagem no console
                else:
                    try:
                        data_readable = cryptosystem.decrypt(data[ID:])

                        # Mostra mensagem de aviso para o cliente, caso data_readable seja vazio
                        if data_readable == "":
                            data_readable = "%s=> Houve algum problema no recebimento da mensagem!" % (ENDL)
                            data_readable += "%s   1. Ou tente ajustar o criptossistema para %s." % (
                            ENDL, ('SDES' if CRIPT == 'r' else 'RC4'))
                            data_readable += "%s   2. Ou envie %s<senha> para mudar a senha diretamente." % (
                            ENDL, ALTER_PASS)
                            data_readable += "%s   3. Ou envie %s para solicitar a chave pública de outro cliente." % (
                            ENDL, GET_PUBKEY)
                            data_readable += "%s   4. Ou apenas ignore e aguarde novas mensagens." % (ENDL)

                        print '%sRecebido: %s %s' % (ENDL, (BLUE + str(data[:ID]) + str(data_readable) + NORMAL), ENDL)

                    except:
                        print '(      Cliente     ) Erro ao tentar descriptografar a mensagem! %s' % (ENDL)

    except socket.timeout:
        data = ''
    # Socket permanece em espera
    # print '%s[Socket em standby...]' % (ENDL)

# Fecha socket
print '[Fechando socket...] %s' % (ENDL)
sock.close()
sys.exit()
