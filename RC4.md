RC4
--

@brief _Classe para criptografia de mensagens usando RC4_


Classe RC4
--

Visão Geral
- A classe RC4 recebe uma mensagem que será criptografada e posteriomente enviada pelo client_chat.
- A classe RC4 também serve para decriptar as mensagem que compartilhem a mesma chave.


Métodos
--

**Construtor __init__()**
- Inicializa a variável PASS_RC4 (chave secreta usada pelo RC4)

**ksa()**
- Usada para inicializar a permutação no array S. K.Length é definido como o número de bytes na chave e pode variar entre 1 e 256.

**prga()**
- O PRGA modifica o estado e a saída do byte resultante em cada repetição.

**charToInt()**
- Transforma a msg em uma lista de inteiros.

**encrypt()**
- Encripta a mensagem com RC4.

**decrypt()**
- Decripta a mensagem com RC4.
