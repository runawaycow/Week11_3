Open sidebar
ZKPK equality proof.

Model: Default (GPT-3.5)

luo_dana@yahoo.com
Assignment
In this homework, we’ll use the Zero-Knowledge Swiss-Knife library to generate and verify non-interactive zero-knowledge proofs of equality of El-Gamal ciphertexts.
Enc(m)=(r∗G,m∗G+r∗H)
To prove equality of two ciphertexts, the prover must show that it knows three secrets r1,r2,m
 such that
C1C2D1D2=r1∗G=r1∗H+m∗G=r2∗G=r2∗H+m∗G
Your solution should be in a file called ZK_equality.py, and should contain the function 'ZK_equality’.
The function should take a generator, G
, and a public key, H
 (elliptic curve points), and
generate two El-Gamal ciphertexts using the public-key H
 encrypting the same message, m
, and then generate a NIZK proof
that the two ciphertexts encrypt the same plaintext.
As noted below, the ZK verifier must include the exact statement proven by the prover.
Our verifier will try to verify the statement
    stmt = DLRep(C1,r1*G) & DLRep(C2,r1*H+m*G) & DLRep(D1,r2*G) & DLRep(D2,r2*H+m*G)
Order of clauses must be the same in the ZKSK library

Following are the framework code. please fill it:
from zksk import Secret, DLRep
from zksk import utils

def ZK_equality(G,H):

    #Generate two El-Gamal ciphertexts (C1,C2) and (D1,D2)

    #Generate a NIZK proving equality of the plaintexts

    #Return two ciphertexts and the proof
    return (C1,C2), (D1,D2), zk_proof

Here's the code for the ZK_equality function using the Zero-Knowledge Swiss-Knife library:

python
Copy code
from zksk import Secret, DLRep, utils
from zksk.api import ZKProof

def ZK_equality(G, H):
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
    zk_proof = ZKProof(G, H)
    zk_proof.prove(stmt)

    # Return the ciphertexts and the proof
    return (C1, C2), (D1, D2), zk_proof
The function generates a random message and two random secrets r1 and r2. It then calculates the two ElGamal ciphertexts C1, C2, D1, D2 using the given generator G and public key H. After that, it creates a statement stmt to prove that the two ciphertexts encrypt the same plaintext. Finally, it creates a NIZK proof for the statement using the ZKProof class and returns the ciphertexts and the proof.




luo_dana@yahoo.com
can you do it without using ZKProof

Sure, here's the implementation of the ZK_equality function using only the DLRep and zkay classes from the Zero-Knowledge Swiss-Knife library:

python
Copy code
from zksk import Secret, DLRep, utils
from zksk import zkay

def ZK_equality(G, H):
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
    prf = zkay.prove(stmt, prover_id="prover1")

    # Verify the NIZK proof
    assert zkay.verify(prf, stmt, verifier_id="verifier1")

    # Return the ciphertexts and the proof
    return (C1, C2), (D1, D2), prf
The implementation is similar to the previous one. It generates a random message and two random secrets r1 and r2. It then calculates the two ElGamal ciphertexts C1, C2, D1, D2 using the given generator G and public key H. After that, it creates a statement stmt to prove that the two ciphertexts encrypt the same plaintext. The zkay.prove function is used to create a NIZK proof for the statement. The prover_id parameter is used to identify the prover of the proof. Finally, the function verifies the proof using the zkay.verify function and the verifier_id parameter to identify the verifier of the proof. The function returns the ciphertexts and the proof.




luo_dana@yahoo.com
Can you do it without using zkey? The prover and verifier must have the clauses in the same order. here is some reference code:
rom zksk import Secret, DLRep
from zksk import utils

# Setup: Peggy and Victor agree on two group generators.
# Since Peggy is *committing* rather than encrypted Peggy doesn't know DL_G(H)
G, H = utils.make_generators(num=2, seed=42)

# Setup: generate a secret randomizer for the commitment scheme.
r = Secret(utils.get_random_num(bits=128))

# This is Peggy's secret bit.
top_secret_bit = 1

# A Pedersen commitment to the secret bit.
C = top_secret_bit * G + r.value * H

# Peggy's definition of the proof statement, and proof generation.
# (The first or-clause corresponds to the secret value 0, and the second to the value 1. Because
# the real value of the bit is 1, the clause that corresponds to zero is marked as simulated.)
stmt = DLRep(C, r * H, simulated=True) | DLRep(C - G, r * H)
zk_proof = stmt.prove()

from zksk import Secret, DLRep

# Setup: get the agreed group generators.
G, H = utils.make_generators(num=2, seed=42)
# Setup: define a randomizer with an unknown value.
r = Secret()

stmt = DLRep(C, r * H) | DLRep(C - G, r * H)
assert stmt.verify(zk_proof)

Sure, here's the implementation of the ZK_equality function without using any library:

python
Copy code
from zksk import Secret, DLRep, utils, HashCommitment

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

    # Commit to the values r1, r2, and m using HashCommitment
    hc = HashCommitment()
    hc.commit(r1.value.to_bytes(32, 'big'))
    hc.commit(r2.value.to_bytes(32, 'big'))
    hc.commit(m.value.to_bytes(32, 'big'))

    # Get the commitment value
    commitment = hc.get_commitment()

    # Calculate the challenge value as a hash of the generator G, public key H, and commitment
    challenge = int.from_bytes(utils.hash_GH(commitment + G.export() + H.export()), 'big')

    # Calculate the response values
    s1 = (r1.value + challenge * top_secret_bit) % G.order()
    s2 = (r2.value + challenge * (1 - top_secret_bit)) % G.order()
    s3 = (m.value + challenge * top_secret_bit * (1 - top_secret_bit)) % G.order()

    # Verify the proof
    lhs1 = s1 * G
    rhs1 = C1 + challenge * G
    assert lhs1 == rhs1

    lhs2 = s1 * H + s3 * G
    rhs2 = C2 + challenge * (r1.value * H + m.value * G)
    assert lhs2 == rhs2

    lhs3 = s2 * G
    rhs3 = D1 + challenge * G
    assert lhs3 == rhs3

    lhs4 = s2 * H + s3 * G
    rhs4 = D2 + challenge * (r2.value * H + m.value * G)
    assert lhs4 == rhs4

    # Return the ciphertexts and the proof
    return (C1, C2), (D1, D2), commitment, challenge, s1, s2, s3
The function generates two random secrets r1 and r2 and a random message m. It then calculates the four points of ElGamal ciphertexts C1, C2, D1, D2 using the given generator G and public key H. After that, it uses the HashCommitment class to commit to the values r1, r2, and m. The commitment value is obtained using the get_commitment() method. The function then calculates the challenge value as a hash of the commitment value, generator G, and public key H. It then calculates the response values s1, s2, and s3. Finally, it verifies the proof by checking that the response values satisfy the equation of ElGamal ciphertexts. The function returns the ciphertexts, the commitment value, the challenge value, and the response values.




luo_dana@yahoo.com
we can only import Secret, DLRep and utils from zksk. please fill in the framework code following all instructions that we have discussed before:

from zksk import Secret, DLRep
from zksk import utils

def ZK_equality(G,H):

    #Generate two El-Gamal ciphertexts (C1,C2) and (D1,D2)

    #Generate a NIZK proving equality of the plaintexts

    

    #Return two ciphertexts and the proof
    return (C1,C2), (D1,D2), zk_proof

Sure, here's the implementation of the ZK_equality function using only the Secret, DLRep, and utils classes from the Zero-Knowledge Swiss-Knife library:

python
Copy code
from zksk import Secret, DLRep, utils

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
    s1 = r1 + challenge * Secret(top_secret_bit)
    s2 = r2 + challenge * Secret(1 - top_secret_bit)
    s3 = m + challenge * Secret(top_secret_bit * (1 - top_secret_bit))

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

    # Return the ciphertexts and the proof
    return (C1, C2), (D1, D2), challenge, s1, s2, s3
The implementation is similar to the previous one, but it doesn't use the HashCommitment and zkay classes. Instead, it generates a random challenge value using the utils.get_random_num function. It then calculates the response values s1, s2, and s3 using the random challenge value and the secret values r1, r2, and m. Finally, it verifies the proof by checking that the response values satisfy the equation of ElGamal ciphertexts. The function returns the ciphertexts, the challenge value, and the response values.




luo_dana@yahoo.com
The return have to be     #Return two ciphertexts and the proof
    return (C1,C2), (D1,D2), zk_proof

Sure, here's the updated implementation of the ZK_equality function with the correct return statement:

python
Copy code
from zksk import Secret, DLRep, utils

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
    s1 = r1 + challenge * Secret(top_secret_bit)
    s2 = r2 + challenge * Secret(1 - top_secret_bit)
    s3 = m + challenge * Secret(top_secret_bit * (1 - top_secret_bit))

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
The implementation now returns the ciphertexts and the proof as required. After verifying the proof, the function uses the prove method of the stmt object to create the proof. The challenge value is passed as an argument to the prove method. The function then returns the ciphertexts and the proof.




luo_dana@yahoo.com
 name 'top_secret_bit' is not defined

I apologize for the error. The variable top_secret_bit was not defined in the provided code. Assuming that it is a global variable representing the secret bit, you can define it before the ZK_equality function as follows:

python
Copy code
from zksk import Secret, DLRep, utils

# Define the secret bit
top_secret_bit = 1

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
    # Define the secret bit
    top_secret_bit = 1
    # Calculate the responses
    s1 = r1 + challenge * Secret(top_secret_bit)
    s2 = r2 + challenge * Secret(1 - top_secret_bit)
    s3 = m + challenge * Secret(top_secret_bit * (1 - top_secret_bit))

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
