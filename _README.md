README
--

@brief _Informações gerais sobre o projeto_

**Projeto 1** da disciplina **IMD0703 Segurança de Redes**, ministrada pelo Prof. Silvio Sampaio no curso BTI da UFRN.


Programa
--

_Chat Criptografado via TCP/IP_


Objetivo
--

- Este projeto tem como objetivo a **implementação de um chat via protocolo TCP/IP** que utiliza os criptossistemas _SDES_ e  _RC4_ para troca de mensagens e o método criptográfico _DiffieHellman_ para troca de chaves.


Orientações sobre o funcionamento do chat
--

- Ativar o **servidor** (host_chat.py) passando via linha de comando o **IP** e a **Porta** que o servidor deve usar;
- Ativar os **clientes** (client_chat.py) passando via linha de comando o **IP** e a **Porta do servidor**;
- Se o servidor e os clientes estiverem em **redes distintas**, faz-se necessário utilizar o **IP externo do servidor** e verificar se os roteamentos necessários entre o _gateway_ e o servidor foram feitos adequadamente;
- Se um novo cliente não conseguir decifrar as mensagens recebidas, faz-se necessário **ajustar o criptossistema e/ou a senha/chave secreta da sessão**:
	- Primeiro, é necessário ajustar o criptossistema alternando entre SDES e RC4 (e vice-versa);
	- Segundo, é necessário ajustar a senha diretamente, se o cliente souber, ou solicitar a chave pública de um outro cliente.