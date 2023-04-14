from zksk import Secret, DLRep
from zksk import utils

def ZK_equality(G,H):

    #Generate two El-Gamal ciphertexts (C1,C2) and (D1,D2)

    #Generate a NIZK proving equality of the plaintexts
    # Generate a random message and two random secrets r1, r2
    m = Secret(utils.get_random_num(bits=256))
    r1 = Secret(utils.get_random_num(bits=256))
    r2 = Secret(utils.get_random_num(bits=256))

    # Calculate the two ElGamal ciphertexts
    C1 = r1.value * G
    C2 = r1.value * H + m.value * G
    D1 = r2.value * G
    D2 = r2.value * H + m.value * G

    # Create the NIZK proof
    stmt = DLRep(C1, r1 * G) & DLRep(C2, r1 * H + m * G) & DLRep(D1, r2 * G) & DLRep(D2, r2 * H + m * G)
    #zk_proof = ZKProof(G, H)
    zk_proof = zkay.prove(stmt, prover_id="prover1")

    # Verify the NIZK proof
    assert zkay.verify(zk_proof, stmt, verifier_id="verifier1")


    #Return two ciphertexts and the proof
    return (C1,C2), (D1,D2), zk_proof

