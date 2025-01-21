import time
import hashlib

# Helper function for hashing
def hash_function(data):
    return int(hashlib.sha256(data.encode()).hexdigest(), 16)

# Constants
public_key = 12345  # Example public key
private_key = 67890  # Example private key
RID_TA = "ExampleIdentity"  # Identity
T1 = 123456  # Timestamp

delta_T = 5  # Maximum transmission delay in seconds
bi = hash_function(RID_TA + str(T1))
M1 = private_key * public_key
bi_Q = bi * public_key
M2 = private_key + bi
M2_P = M2 * public_key
M1_biQ = M1 + bi_Q

# Step AKE1: CNj processes the login request
T1_received = T1 + 1  # Simulated received time (within delta_T)

if abs(T1_received - T1) < delta_T:
    # Compute bi and verify signature
    bi = hash_function(RID_TA + str(T1))
    bi_Q = bi * public_key
    M2_P = M2 * public_key
    M1_biQ = M1 + bi_Q

    if M2_P == M1_biQ:
        print("Signature verification succeeded.")

        # Generate T2 and rj
        T2 = int(time.time())
        rj = hash_function(str(time.time())) % (2**160)

        # Compute cj, M4, kij, SKij, and M5
        cj = hash_function(f"{rj}{T2}{RID_TA}")
        M4 = cj * public_key
        kij = cj * M1
        SKij = hash_function(f"{kij}{RID_TA}{T1}{T2}")
        M5 = hash_function(f"{SKij}{T2}")

        # Send M4, M5, T2 to Ui
        print(f"Send to Ui: M4={M4}, M5={M5}, T2={T2}")
    else:
        print("Signature verification failed. Terminating connection.")
        exit()
else:
    print("T1 timeliness check failed. Terminating connection.")
    exit()

# Step AKE2: Ui processes the authentication reply
T2_received = T2  # Simulated received time (within delta_T)

if abs(T2_received - T2) < delta_T:
    # Compute k_ij_star and session key SKij_star
    k_ij_star = private_key * M4
    SKij_star = hash_function(f"{k_ij_star}{RID_TA}{T1}{T2}")
    M6 = hash_function(f"{SKij_star}{T2}")

    if M6 == M5:
        print("CNj authenticated by Ui.")

        # Generate T3 and M7
        T3 = int(time.time())
        M7 = hash_function(f"{SKij_star}{T3}")

        # Send M7, T3 to CNj
        print(f"Send to CNj: M7={M7}, T3={T3}")
    else:
        print("Authentication reply verification failed. Terminating connection.")
        exit()
else:
    print("T2 timeliness check failed. Terminating connection.")
    exit()

# Step AKE3: CNj processes acknowledgment
T3_received = T3  # Simulated received time (within delta_T)

if abs(T3_received - T3) < delta_T:
    M8 = hash_function(f"{SKij}{T3}")
    if M8 == M7:
        print("Ui authenticated by CNj. Session key established.")
        print(f"Shared Session Key: {SKij}")
    else:
        print("Acknowledgment verification failed. Terminating connection.")
else:
    print("T3 timeliness check failed. Terminating connection.")
