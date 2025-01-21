import hashlib
import random
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import hashlib
import random
import time

# Step REG1: Registration request from User (Ui) to Trusted Authority (TA)
def registration_step_1(IDi, N):
    RIDi = hashlib.sha256((IDi + str(N)).encode()).hexdigest()
    Ai = hashlib.sha256((RIDi + IDi).encode()).hexdigest()
    RIDTA = hashlib.sha256((IDi + str(N)).encode()).hexdigest()
    return RIDi, Ai, RIDTA

# Step REG2: Elliptic curve and key generation
def registration_step_2():
    # Generate an elliptic curve
    curve = ec.SECP256R1()  # Using the SECP256R1 curve (equivalent to Ep in the steps)
    private_key = ec.generate_private_key(curve, default_backend())  # Ui selects a private key
    public_key = private_key.public_key()  # Compute the corresponding public key
    return private_key, public_key

# Step REG3: Fuzzy extractor and biometric input
def fuzzy_extractor(BIOi):
    # Use simple hash for biometric input as a placeholder for fuzzy extractor
    σi = hashlib.sha256(BIOi.encode()).hexdigest()
    τi = hashlib.sha256(σi.encode()).hexdigest()  # Corresponding public parameter
    return σi, τi

# Step REG4: Password-based computations
def registration_step_4(IDi, PWi, σi, k, RIDi, RIDTA, Ai):
    # Password and biometric key processing
    RIDi_ = int(RIDi, 16) ^ int(hashlib.sha256((PWi + σi).encode()).hexdigest(), 16)
    RPWi = hashlib.sha256((PWi + str(k)).encode()).hexdigest()
    Di = k ^ int(hashlib.sha256((IDi + PWi + σi).encode()).hexdigest(), 16)
    RIDTA_ = int(RIDTA, 16) ^ int(hashlib.sha256((IDi + str(k) + σi).encode()).hexdigest(), 16)
    Ai_ = int(Ai, 16) ^ int(hashlib.sha256((str(k) + σi).encode()).hexdigest(), 16)
    
    # Additional computations
    Bi = hashlib.sha256((str(Ai_) + RPWi).encode()).hexdigest()
    Ci = hashlib.sha256((IDi + RIDTA + Bi + σi).encode()).hexdigest()
    
    return RIDi_, RIDTA_, Ai_, Bi, Ci, Di, RPWi

# Example usage

# Step REG1
IDi = "user123"
N = random.randint(1000, 9999)
RIDi, Ai, RIDTA = registration_step_1(IDi, N)

# Step REG2
private_key, public_key = registration_step_2()

# Step REG3
BIOi = "user_biometric_data"
σi, τi = fuzzy_extractor(BIOi)

# Step REG4
PWi = "user_password"
k = random.randint(1000, 9999)  # Example private key chosen by the user
RIDi_, RIDTA_, Ai_, Bi, Ci, Di, RPWi = registration_step_4(IDi, PWi, σi, k, RIDi, RIDTA, Ai)

# Serializing the 
pem_public_key = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)


#Print the generated values
print("Step REG1 - RIDi:", RIDi)
print("Step REG1 - Ai:", Ai)
# print("Step REG2 - Public Key:", pem_public_key.decode())
print("Step REG3 - Biometric Key:", σi)
print("Step REG3 - Public Parameter:", τi)
print("Step REG4 - RIDi_:", hex(RIDi_))
print("Step REG4 - RIDTA_:", RIDTA_)
print("Step REG4 - Ai_:", hex(Ai_))
print("Step REG4 - Bi:", Bi)
print("Step REG4 - Ci:", Ci)
print("Step REG4 - Di:", Di)
print("Step REG4 - RPWi:", RPWi)
print("\n")

RIDTA_=hex(RIDTA_)
RIDi_=hex(RIDi_)
Ai_=hex(Ai_)


# Simulated function for fuzzy extractor's replication step (to extract biometric key)
def Rep(BIO_i, τ_i, t):
    σi = hashlib.sha256(BIO_i.encode()).hexdigest()
    τi = hashlib.sha256(σi.encode()).hexdigest()  # Corresponding public parameter
    return σi

# Simulate the Hamming distance calculation between two strings (biometric data)
def HammingDistance(str1, str2):
    return sum(el1 != el2 for el1, el2 in zip(str1, str2))

# Step L1: Login phase - Password and biometric verification
def login_step_1(IDi, PWi, BIO_i, σ_i, τ_i, t, Di, Ai, RID_TA, Ci):
    # Replication of the biometric key
    σ_star_i = Rep(BIO_i, τ_i, t)
    if σ_star_i is None:
        return "Biometric mismatch! Login failed."
    
    # Compute k_star
    k_star = Di ^ int(hashlib.sha256((IDi + PWi + σ_star_i).encode()).hexdigest(), 16)
    
    # Compute RPW_star_i - Correct
    RPW_star_i = hashlib.sha256((PWi + str(k_star)).encode()).hexdigest()
    
    # Compute A_star_i
    A_star_i = int(Ai, 16) ^ int(hashlib.sha256((str(k_star) + σ_star_i).encode()).hexdigest(), 16)
    
    # Compute B_star_i - Correct
    B_star_i = hashlib.sha256((str(A_star_i) + RPW_star_i).encode()).hexdigest()
    
    # Compute RID_star_TA and RID_star_i
    RID_star_TA = int(RID_TA, 16) ^ int(hashlib.sha256((IDi + str(k_star) + σ_star_i).encode()).hexdigest(), 16)
    RID_star_i = int(RIDi, 16) ^ int(hashlib.sha256((PWi + σ_star_i).encode()).hexdigest(), 16)
    # Compute C_star_i
    C_star_i = hashlib.sha256((IDi + str(RID_star_TA) + B_star_i + σ_star_i).encode()).hexdigest()
    C_original = hashlib.sha256((IDi + RIDTA + Bi + σi).encode()).hexdigest()

    # Check if C_star_i matches Ci
    if C_original != Ci:
        return "Password or biometric verification failed! Login terminated."
    
    return k_star, A_star_i, B_star_i, RID_star_TA, RID_star_i, C_star_i

# Step L2: Timestamp and nonce generation, ElGamal-like signature
def login_step_2(k_star, RID_star_i, RPW_star_i, σ_star_i, p, P):
    # Generate current timestamp and random nonce
    T1 = int(time.time())  # Current timestamp
    ri = random.getrandbits(160)  # 160-bit random nonce
    
    # Compute a_i and b_i
    a_i = hashlib.sha256((str(ri) + str(T1) + str(RID_star_i) + RPW_star_i + σ_star_i).encode()).hexdigest()
    b_i = hashlib.sha256((str(RID_star_i) + str(T1)).encode()).hexdigest()
    
    # ElGamal-like signature
    M1 = int(a_i, 16) * P  # Multiply by base point P
    M2 = (int(a_i, 16) + k_star * int(b_i, 16)) % p  # Modulo p (ElGamal signature step)
    
    return M1, M2, T1

t =2 
# Step L1: Login Phase - Verification
login_result = login_step_1(IDi, PWi, BIOi, σi, τi, t, Di, Ai, RIDTA_, Ci)
if isinstance(login_result, str):
    print(login_result)
else:
    k_star, A_star_i, B_star_i, RID_star_TA, RID_star_i, C_star_i = login_result
    print("Step L1 - Login successful!")

    # Step L2: Generate Timestamp and Signature
    p = 1009  # Example prime number for the ElGamal signature
    P = 2  # Example base point (usually part of the elliptic curve setup)
    M1, M2, T1 = login_step_2(k_star, RID_star_i, hashlib.sha256((PWi + str(k_star)).encode()).hexdigest(), σi, p, P)
    print("Step L2 - Login request message:","Hi, I am", IDi, "and I want to login. Here is my signature:")
    print("M1:", M1)
    print("M2:", M2)
    print("T1:", T1)
    

    
