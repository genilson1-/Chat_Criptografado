SDES 
--

@brief _Classe para criptografia de mensagens usando SDES_


Classe SDES
--

Visão geral
- A classe SDES recebe uma mensagem que será criptografada e posteriomente enviada pelo client_chat.
- A classe SDES também serve para decriptar as mensagem que compartilhem a mesma chave.


Métodos
--

**Construtor __init__()**
- Inicializa a variável PASS_SDES (chave usada na criptografia e decriptografia).

**BinToInt()**
- Pega o valor do char e converte para inteiro.

**swap()**
- Troca os 4 últimos bits de cada caracter pelos 4 primeiros.

**permutacao()**
- Faz as permutações das mensagens a partir das réguas.

**recuperaMsg()**
- Recupera a mensagem que antes estava em bits para char.

**leftShift()**
- Faz o deslocamento na cadeia de bits.

**keyK1()**
- Função responsável por gerar a chave k1.

**keyK2()**
- Função responsável por gerar a chave k2.

**functionK1()**
- Função complexa 1, faz as operações para a encriptação da mensagem.

**functionK2()**
- Função complexa 2, faz as operações para a encriptação da mensagem.

**box()**
- Mais uma etapa de manipulação dos bits da mensagem.

**encrypt()**
- Encripta a mensagem que será enviada.

**ecrypt()**
- Decripta a mensagem que foi recebida.


