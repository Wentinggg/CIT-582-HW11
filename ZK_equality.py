from zksk import Secret, DLRep
from zksk import utils

'''
The function should take a generator, G, and a public key, H(elliptic curve points),
and generate two El-Gamal ciphertexts using the public-key H encrypting the same message,
m, and then generate a NIZK proof that the two ciphertexts encrypt the same plaintext.
The ZK verifier must include the exact statement proven by the prover.
Verify: stmt = DLRep(C1,r1*G) & DLRep(C2,r1*H+m*G) & DLRep(D1,r2*G) & DLRep(D2,r2*H+m*G).
Order of clauses must be the same in the ZKSK library.
'''
def ZK_equality(G, H):
    # Generate two El-Gamal ciphertexts (C1,C2) and (D1,D2)
    r1 = Secret(utils.get_random_num(bits=128))
    r2 = Secret(utils.get_random_num(bits=128))
    m = 1
    C1 = r1.value * G
    C2 = m * G + r1.value * H

    D1 = r2.value * G
    D2 = m * G + r2.value * H

    # Generate a NIZK proving equality of the plaintexts
    stmt = DLRep(C1, r1 * G) & DLRep(C2, r1 * H + m * G) & DLRep(D1, r2 * G) & DLRep(D2, r2 * H + m * G)
    zk_proof = stmt.prove()

    # Return two ciphertexts and the proof
    return (C1, C2), (D1, D2), zk_proof
