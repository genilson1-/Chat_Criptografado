Diffie-Hellman
--

@brief _Método de criptografia para troca de chaves_


Classe DiffieHellman
--

Responsável pela **troca de chaves** entre usuários utilizando o método _Diffie-Hellman_.


Métodos
--

**Construtor __init__()**
- Inicializa váriaveis (PRIMO e ALFA).

**calcPub()**
- Calcula a chave pública de acordo com a chave privada do usuário.

**calcKeySession()**
- Calcula a chave secreta da sessão utilizando a chave privada de um usuário 'A' com a chave pública de um usuário 'B'.

**setPrimo()**
- Altera o número PRIMO

**setAlfa()**
- Altera o ALFA que é raiz primitiva de PRIMO