Cliente Chat
--

@brief _Cliente de Chat via TCP/IP_


Cliente TCP/IP
--

Conecta com o host para enviar e receber mensagens.


Visão geral
--

- O script **client_chat.py** recebe como argumentos um **IP ou hostname** e uma **porta** do host/servidor via linha de comando para criar e conectar um **socket** ao host.
- As mensagens enviadas e recebidas são criptografadas utilizando a classe **SDES** ou **RC4**.
- Para troca de chaves é utilizado a classe **DiffieHellman**.


Funções
--

**clearConsole()**
- Função para limpar console.

**formatPass()**
- Função pra formatar a chave digitada pelo usuário.

**notifyDH()**
- Função para notificar aos outros clientes sobre a mudança de chave (envia chave pública).

**alterMyKeyPair()**
- Função para alterar o par de chaves (privado, público) do cliente.

**alterPass()**
- Função para alterar a senha/chave secreta da sessão.

**alterCript()**
- Função para alterar criptossistema utilizado na troca de mensagens (SDES ou RC4).

**readInputSend()**
- Função para ler mensagem do usuário e enviar via socket ao host TCP/IP.

**handlerThread()**
- Função para tratamento multi-thread.
- Usada para chamar outras funções para serem executadas via Thread.