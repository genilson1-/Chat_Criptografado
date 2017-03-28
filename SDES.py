#!/usr/bin/env python
# -*- coding: utf-8 -*-

##	@file 		SDES.py
#	@brief 		Criptossistema de encriptação e decriptação SDES
#	@details 	Responsável pela criptografia das mensagens enviadas no chat
#	@since		09/09/2016
#	@date		30/09/2016
#	@authors	David e Genilson
#	@copyright	2016 - All rights reserveds
#	@sa 		http://projetos.imd.ufrn.br/davidcardoso-ti/imd0703/blob/master/chat_criptografado/SDES.py


class SDES(object):
    global REG_P10, REG_P8, REG_EP, REG_P4, BOX_S1, BOX_S2, LINHA, COLUNA, msg
    REG_P10 = (3, 5, 2, 7, 4, 10, 1, 9, 8, 6)  # < REG_P10 - régua de permutação P10
    REG_P8 = (6, 3, 7, 4, 8, 5, 10, 9)  # < REG_P8  - régua de permutação P8
    REG_EP = (4, 1, 2, 3, 2, 3, 4, 1)  # < REG_EP  - régua de permutação e expansão EP
    REG_P4 = (2, 4, 3, 1)  # < REG_P4  - régua de permutação de P4
    BOX_S1 = ([1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 3, 2])  # < BOX_S1  - caixa 1 de troca dos bits
    BOX_S2 = ([1, 1, 2, 3], [2, 0, 1, 3], [3, 0, 1, 0], [2, 1, 0, 3])  # < BOX_S2  - caixa 2 de troca dos bits
    LINHA = (1, 4)  # < LINHA   - linha da caixa selecionada
    COLUNA = (2, 3)  # < COLUNA  - coluna da caixa selecionada

    ## 	@brief Construtor __init__() da classe SDES
    #	@details inicializa o valor da chave,
    #	@param PASS_SDES     - chave usada na cifra e tem um valor default
    def __init__(self, PASS_SDES='0010100000'):
        self.key = PASS_SDES

    ## 	@brief Função BinToInt()
    #   @details Pega o valor do char e converte para inteiro
    #   @param msg      - caracter da mensagem a ser convertido
    #   @return result  - retorna uma lista de inteiro que representa o valor binário do caracter
    def BinToInt(self, msg):
        result = []
        bi = bin(ord(msg))[2:].zfill(8)
        for value in bi:
            result.append(int(value))
        return (result)

    ##  @brief Função swap()
    #   @details Troca os 4 últimos bits de cada caracter pelos 4 primeiros
    #   @param msg_bin            - binário para ser trocado
    #   @return (right + left)    - cadeia de binário com a troca feita
    def swap(self, msg_bin):
        left = msg_bin[:4]
        right = msg_bin[4:]
        return (right + left)

    ##  @brief Função encrypt()
    #   @details Encripta a mensagem que será enviada
    #   @param msg                  - É a mensagem que será encriptada
    #   @return result              - Retorna a mensagem encriptada
    def encrypt(self, msg):
        result = ''  # < result - Recebe a mesangem encriptada
        for char in msg:
            dec = self.BinToInt(char)
            (s1, s2, bi_left, bi_right) = self.functionK1(dec)
            x = self.box(s1, s2, bi_left, bi_right)
            troca = self.swap(x)
            (s1, s2, bi_left, bi_right) = self.functionK2(troca)
            y = self.box(s1, s2, bi_left, bi_right)
            y = "".join("%d" % n for n in y)
            result += (y).zfill(8)
        return (result)

    ##  @brief Função decrypt()
    #   @details Decripta a mensagem que foi recebida
    #   @param msg                  - É a mensagem que será decriptada
    #   @return result              - Retorna a mensagem decriptada
    def decrypt(self, msg):
        result = ''  # < result - Recebe a mesangem encriptada
        msgg = self.recuperaMsg(msg)
        for char in msgg:
            dec = self.BinToInt(char)
            (s1, s2, bi_left, bi_right) = self.functionK2(dec)
            x = self.box(s1, s2, bi_left, bi_right)
            troca = self.swap(x)
            (s1, s2, bi_left, bi_right) = self.functionK1(troca)
            y = self.box(s1, s2, bi_left, bi_right)
            y = "".join("%d" % n for n in y)
            result += (y).zfill(8)
        result = self.recuperaMsg(result)
        return (result)

    ##  @brief Função permutacao()
    #   @details Faz as permutações das mensagens a partir das réguas
    #   @param vetor_permuta        - Vetor que será permutado
    #   @param regua                - Régua que controla a permuta
    #   @return result              - retorna uma lista contendo a permuta do binário
    def permutacao(self, vetor_permuta, regua):
        list_ = []
        for value in regua:
            list_.append(int(vetor_permuta[value - 1]))
        return (list_)

    ##  @brief Função leftShift()
    #   @details Faz o deslocamento na cadeia de bits
    #   @param vector_bits      - Vetor de bits que será deslocado
    #   @param desloca          - Diz de quanto será a deslocação do vetor
    #   @return list_           - Retorna uma lista com o vetor deslocado
    def leftShift(self, vector_bits, desloca):
        list_ = []
        for index, y in enumerate(vector_bits):
            list_.append(vector_bits[(index + desloca) % len(vector_bits)])
        return list_

    ##  @brief Função keyK1()
    #   @details Função responsável por gerar a chave k1
    #   @return (k1, aux) - retorna a chave k1 aux recebe o vetor concatenado depois do leftshift
    def keyK1(self):
        # primeira permuta
        k1_permuta = self.permutacao(self.key, REG_P10)
        # quebra em dois o valor permutado
        k1_left = k1_permuta[:5]
        k1_right = k1_permuta[5:]
        # concatena os valores deslocados leftShift-1
        aux = self.leftShift(k1_left, 1) + self.leftShift(k1_right, 1)
        # permuta novamente a concatenação acima
        k1 = self.permutacao(aux, REG_P8)
        return (k1, aux)

    ##  @brief Função keyK2()
    #   @details Função responsável por gerar a chave k2
    #   @return (k1, aux) - retorna a chave k2
    def keyK2(self):
        (lixo, k2_inicial) = self.keyK1()
        s1 = k2_inicial[:5]
        s2 = k2_inicial[5:]
        aux = self.leftShift(s1, 2) + self.leftShift(s2, 2)
        k2 = self.permutacao(aux, REG_P8)
        return k2

    ##  @brief Função functionK1()
    #   @details Função complexa 1, faz as operações para a encriptação da mensagem
    #   @param msg                          - Mensagem que passará pela função complexa
    #   @return s1, s2, bi_left, bi_right   - s1 são os primeros 4 bits do primeiro xor, s2 são os 4 últimos
    def functionK1(self, msg):
        # transforma a mensagem em binário
        bi_left = (msg)[:4]  # < bi_left  - parte esquerda da mensagem
        bi_right = (msg)[4:]  # < bi_right - parte esquerda da mensagem
        # resutado do XOR
        xor_result = []
        # pega os bits da mensagem e faz um vetor de int
        # permutação com REG_EP
        ep_ = self.permutacao(bi_right, REG_EP)
        (k1, lixo) = self.keyK1()
        for index, value in enumerate(k1):
            xor_result.append(int(value ^ ep_[index]))
        s1 = xor_result[:4]
        s2 = xor_result[4:]
        return (s1, s2, bi_left, bi_right)

    ##  @brief Função functionK2()
    #   @details Função complexa 2, faz as operações para a encriptação da mensagem
    #   @param msg                          - Mensagem que passará pela função complexa
    #   @return s1, s2, bi_left, bi_right   - s1 são os primeros 4 bits do segundo xor, s2 são os 4 últimos
    def functionK2(self, msg):
        # transforma a mensagem em binário
        bi_left = (msg)[:4]
        bi_right = (msg)[4:]
        # resutado do XOR
        xor_result = []
        # permutação com REG_EP
        ep_ = self.permutacao(bi_right, REG_EP)
        k2 = self.keyK2()
        for x, y in enumerate(k2):
            xor_result.append(int(k2[x] ^ ep_[x]))
        s1 = xor_result[:4]
        s2 = xor_result[4:]
        return (s1, s2, bi_left, bi_right)

    ##  @brief Função box()
    #   @details Mais uma etapa de manipulação dos bits da mensagem
    #   @param s1       - primeiros 4 bits após passar pelas funções complexas
    #   @param s2       - últimos 4 bits após passar pelas funções complexas
    #   @param bi_left  - parte esquerda da mensagem
    #   @param bi_right - parte direita da mensagem
    def box(self, s1, s2, bi_left, bi_right):
        l1 = int((str(s1[0]) + str(s1[3])), 2)
        l2 = int((str(s2[0]) + str(s2[3])), 2)
        c1 = int((str(s1[1]) + str(s1[2])), 2)
        c2 = int((str(s2[1]) + str(s2[2])), 2)
        s_box1 = bin(BOX_S1[l1][c1])[2:].zfill(2)
        s_box2 = bin(BOX_S2[l2][c2])[2:].zfill(2)
        s_box = str(s_box1) + str(s_box2)
        p4_ = self.permutacao(s_box, REG_P4)
        xor_result = []
        for x, y in enumerate(bi_left):
            xor_result.append(int(bi_left[x] ^ p4_[x]))
        return (xor_result + bi_right)

    ##  @brief Função recuperaMsg()
    #   @details Recupera a mensagem que antes estava em bits para char
    #   @param msg      - Mensagem que está em bits
    #   @return message - Mensagem no formato char
    def recuperaMsg(self, msg):
        msg_recover = []
        iterator = 0
        msg = ''.join(map(str, msg))
        for index, value in enumerate(msg):
            if ((index + 1) % 8 == 0):
                msg_recover.append(chr(int(msg[(iterator):(iterator + 8)], 2)))
                iterator += 8
        message = ''.join(map(str, msg_recover))
        return (message)

# if "__main__" == __name__:
# 	c = SDES()
# 	texto = 't c t'
# 	print(c.key)
# 	a = c.encrypt(texto)
# 	b = c.decrypt(a)
# 	print (b)
