#!/usr/bin/env python3

""" Example code for c't article on Hill Cipher implementation
    and Known Plaintext Attack

    by Peter Uelkes """

""" required modules """
import random, textwrap, itertools, math
import numpy as np

""" helper functions, not specific to Hill Cipher """

def determinant(M):
    """ Calculate determinant of square matrix """
    return int(round(np.linalg.det(np.array(M)), 0))

def modular_inverse(a, m):
    """ Determine inverse of a modulo m; if a and m are not co-prime,
        modular inverse does not exist and function returns "none" """
    return pow(a, -1, m)

def vector_matrix_product(v, M, mod):
    """ Determine product of row vector v from left into
        matrix M, reducing results modulo "mod" """
    assert len(v) == len(M), "Matrix/vector dimensions don't match!"
    return [sum([v[r] * M[r][c] for r in range(len(v))]) % mod for c in range(len(M[0]))]

def matrix_matrix_product(A, B, mod):
    """ Determine product of two matrices reducing results modulo "mod" """
    assert len(A[0]) == len(B), "Matrix dimensions don't match!"
    return [[sum(a * b for a, b in zip(A_row, B_col)) % mod for B_col in zip(*B)] for A_row in A]

def transpose_matrix(M):
    """ Transpose matrix M (reflect elements at main diagonal) """
    return [list(i) for i in zip(*M)]

def adjugate_matrix(M):
    """ Determine adjugate matrix (transpose of cofactor matrix) for matrix M """
    n = len(M)
    # alternating signs:
    A = [[(-1)**(r + c) for c in range(n)] for r in range(n)]
    # multiply each (+-1) element with determinant of sub-matrix:
    for r in range(n):
        for c in range(n):
            sub_matrix = [[M[c2][r2] for c2 in range(n) if r2 != c and c2 != r] for r2 in range(n)]
            sub_matrix = [row for row in sub_matrix if len(row) > 0]
            A[r][c] *= determinant(sub_matrix)
    # finally transpose:
    return transpose_matrix(A)

def get_inverse_matrix_mod(M, mod):
    """ Determine inverse of matrix M modulo "mod" by
        Adjugate Method, i.e. use fact that M * Adjugate(M) == det(M) * I_n """
    # get modular inverse of determinant:
    det_inv = modular_inverse(determinant(M) % mod, mod)
    # determine adjugate matrix:
    Ad, n = adjugate_matrix(M), len(M)
    # construct inverse matrix:
    return [[(det_inv * Ad[r][c]) % mod for c in range(n)] for r in range(n)]

def pretty_print_matrix(M, txt = ""):
    """ Neatly print matrix M, use fixed with of three (adapt if
        need for really large alphabet arises) """
    print("\n" + txt)
    frmt = "%3d" * len(M[0])
    for row in M:
        print(frmt % tuple(row))

""" Hill cipher class """

class HillCipher:
    """ Implementation of Hill Cipher. Use convention of multiplying
        plaintext vector from left into key matrix K. """

    # alphabet, use standard english alphabet as default, modify if needed:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    
    def __init__(self, n = 4, K = None):
        """ Init instance of HillCipher class; parameters:
            n: Dimension of matrix (default = 4)
            K: Key matrix (default = None, if no matrix is given,
                                     a ramdon one will be created) """

        # Class variables, matching letters to numbers and vice versa:
        HillCipher.N = len(HillCipher.alphabet)
        HillCipher.number2letter = {i: HillCipher.alphabet[i] \
                                    for i in range(HillCipher.N)}
        HillCipher.letter2number = {HillCipher.alphabet[i]: i \
                                    for i in range(HillCipher.N)}
    
        # Determine determinant and random key matrix (if required):
        self.n = n
        if K:
            # key matrix provided as a parameter:
            self.K, self.det = K, determinant(K)
            # check if invertible:
            if not math.gcd(self.det, self.N) == 1:
                print("WARNING: matrix is not invertible mod %d!" % N)
                self.K_inv = None
                return
        else:
            # no key matrix provided, so generate one randomly:
            while True:
                # loop until a matrix is found which has a determinant
                # co-prime to N; avoid 0 is entry of key matrix to achieve
                # maxium diffusion:
                self.K = [[random.randint(1, self.N - 1) for _ in range(n)] \
                          for __ in range(n)]
                self.det = determinant(self.K)
                if math.gcd(self.det, self.N) == 1: break
                
        # determine inverse matrix:
        self.K_inv = get_inverse_matrix_mod(self.K, self.N)

    def get_K(self):
        """ Getter method for key matrix K """
        return self.K

    def get_K_inv(self):
        """ Getter method for inverse key matrix K_inv """
        return self.K_inv

    def encrypt(self, msg):
        """ Encrypt message (given by parameter "msg") with Hill cipher """
        cipher = ""
        # blockwise encryption:
        for block in textwrap.wrap(msg, self.n):
            # encrypt one plaintext block, pad by X-ses if necessary:
            while len(block) < self.n: block += 'X'
            # convert letters to numbers:
            numbers = [self.letter2number[b] for b in block]
            # multiply number vector with key matrix:
            encrypted_numbers = vector_matrix_product(numbers, self.K, self.N)
            # convert numbers to letters:
            encrypted_letters = [self.number2letter[e] for e in encrypted_numbers]
            # concatenate to cipher:
            cipher += ''.join(encrypted_letters)
        return cipher

    def decrypt(self, cipher):
        """ Decrypt cipher (given by parameter "cipher") with Hill cipher;
            assume that cipher length is multiple of matrix dimension n """
        if not self.K_inv:
            print("Sorry, no inverse encryption matrix available!")
            return 
        # blockwise decryption:
        msg = ""
        for block in textwrap.wrap(cipher, self.n):
            # decrypt one ciphertext block, convert letters to numbers:
            numbers = [self.letter2number[b] for b in block]
            # multiply cipher vector with inverse key matrix:
            decrypted_numbers = vector_matrix_product(numbers, self.K_inv, self.N)
            # convert numbers to letters:
            decrypted_letters = [self.number2letter[d] for d in decrypted_numbers]
            # concatenate to plaintext (message):
            msg += ''.join(decrypted_letters)
        return msg
    
""" Driver functions for examples from articles in magazine c't """

def part1_secret_agent():
    """ example from first article: secret agent in an foreign land """
    HC = HillCipher(4, [[20, 2, 1, 21], [16, 11, 25, 20], [14, 18, 7, 12], [25, 22, 23, 4]])
    pretty_print_matrix(HC.get_K(), "Example from first article:\n===========================\nkey matrix:")
    pretty_print_matrix(HC.get_K_inv(), "inverse key matrix:")
    msg = "TREFFE KONTAKTPERSON UM DREI UHR IM STADTPARK"
    print("\noriginal msg:      ", msg)
    cipher = HC.encrypt(msg.replace(' ', ''))
    print("cipher:            ", ' '.join(textwrap.wrap(cipher, 5)))
    msg_recov = HC.decrypt(cipher)
    print("recovered message: ", msg_recov)
    
def part2_known_plaintext_attack():
    """ example from second article: recovering the key matrix by known plaintext attack """
    print("\n####################################################################")
    print("\nExample from second article:\n============================")
    n = 4
    random.seed(2718281828459045)
    HC = HillCipher(n)
    K = HC.get_K()
    pretty_print_matrix(K, "key matrix:")
    K_inv = HC.get_K_inv()
    pretty_print_matrix(K_inv, "inverse key matrix:")
    plain = "Ein Teil von jener Kraft, Die stets das Böse will und stets das Gute schafft."
    print("\nplaintext for known plaintext attack:", plain)
    msg = "EINTEILVONJENERKRAFTDIESTETSDASBOESEWILLUNDSTETSDASGUTESCHAFFT"
    T = textwrap.wrap(msg, n)
    while len(T[-1]) < n: T[-1] += 'X'
    print("\noriginal msg:      ", ' '.join(T))
    cipher = HC.encrypt(msg.replace(' ', ''))
    C = textwrap.wrap(cipher, n)
    print("\ncipher:            ", ' '.join(C))
    msg_recov = HC.decrypt(cipher)
    print("\nrecovered message: ", msg_recov)

    # try combinations of n fragments of length n for invertibility
    # of plaintext matrix; make sure fragments start a positions
    # 0, n-1, 2*n-1, ... :  
    for comb in itertools.combinations(list(range(len(T))), n):
        # plaintext matrix for fragment:
        P_txt = [T[i] for i in comb]
        # numbers matrix for fragment:
        P_num = [[HC.letter2number[c] for c in T[i]] for i in comb]
        # is P_num invertible mod 26 ?
        det = determinant(P_num)
        if math.gcd(det, 26) == 1:
            # yeah, it's invertible, so recover K:
            # inverse plaintext matrix:
            P_num_inv = get_inverse_matrix_mod(P_num, 26)
            # ciphertext matrix for fragment:
            C_txt = [C[i] for i in comb]
            # ciphertext numbers matrix for fragment:
            C_num = [[HC.letter2number[c] for c in C[i]] for i in comb]
            # determine key matrix by matrix product P_inv * C (mod 26):
            K_attack = matrix_matrix_product(P_num_inv, C_num, 26)
            # make sure it's the correct key matrix:
            assert K == K_attack
            print("Successful recovery of key matrix from plaintext fragments:", ' '.join(P_txt))
           
# Driver code:            
if __name__ == "__main__":
    # example from first article:
    part1_secret_agent()
    # example from second article:
    part2_known_plaintext_attack()
