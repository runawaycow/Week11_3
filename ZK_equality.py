from zksk import Secret, DLRep, utils

# Define the secret bit
top_secret_bit = Secret(1)

def ZK_equality(G, H):
    # Generate two random secrets r1, r2 and a random message
    r1 = Secret(utils.get_random_num(bits=256))
    r2 = Secret(utils.get_random_num(bits=256))
    m = Secret(utils.get_random_num(bits=256))

    # Calculate the four points of ElGamal ciphertexts
    C1 = r1.value * G
    C2 = r1.value * H + m.value * G
    D1 = r2.value * G
    D2 = r2.value * H + m.value * G

    # Create the NIZK proof
    stmt = DLRep(C1, r1 * G) & DLRep(C2, r1 * H + m * G) & DLRep(D1, r2 * G) & DLRep(D2, r2 * H + m * G)

    # Generate a random challenge value
    challenge = Secret(utils.get_random_num(bits=256))

    # Calculate the responses
    s1 = r1 + challenge * top_secret_bit.value
    s2 = r2 + challenge * (Secret(1) - top_secret_bit).value
    s3 = m + challenge * (top_secret_bit * (Secret(1) - top_secret_bit)).value

    # Verify the proof
    lhs1 = s1.value * G
    rhs1 = C1 + challenge.value * G
    assert lhs1 == rhs1

    lhs2 = s1.value * H + s3.value * G
    rhs2 = C2 + challenge.value * (r1.value * H + m.value * G)
    assert lhs2 == rhs2

    lhs3 = s2.value * G
    rhs3 = D1 + challenge.value * G
    assert lhs3 == rhs3

    lhs4 = s2.value * H + s3.value * G
    rhs4 = D2 + challenge.value * (r2.value * H + m.value * G)
    assert lhs4 == rhs4

    # Create the NIZK proof
    zk_proof = stmt.prove(challenge)

    # Return the ciphertexts and the proof
    return (C1, C2), (D1, D2), zk_proof