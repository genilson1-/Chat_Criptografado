Host Chat
--

@brief _Host de Chat via TCP/IP_


Servidor TCP/IP
--

Responsável por manter a conexão entre os clientes através de sockets via protocolo TCP/IP.


Visão geral
--

- O script **host_chat.py** recebe como argumentos um **IP ou hostname** e uma **porta** via linha de comando para criar e manter um **socket de escuta** que aguarda conexões de clientes.
- O gerenciamento de recebimento e envio de dados é feito através de **eventos** (método poll() do módulo select)


Funções
--

**clearConsole()**
- Função para limpar console

**feedbackClient()**
- Função que manda um feedback ao clientes
- Usado pelo método run() da classe threading

**broadcastClient()**
- Função que manda uma mensagem ao cliente
- Usado pelo método run() da classe threading

**handlerThread()**
- Função para tratamento multi-thread
- Usada para chamar outras funções para serem executadas via Thread.


