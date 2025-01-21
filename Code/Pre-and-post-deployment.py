import hashlib
import random
import time

# Utility function to compute a hash for a given input (for pseudo-identity generation)
def compute_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()

# Polynomial Evaluation: Simulating a simple polynomial key derivation
def evaluate_polynomial(polynomial_share, x, y):
    # Assuming polynomial_share is a dictionary with keys (x, y) -> polynomial value
    # To simulate the polynomial, we combine x and y with polynomial coefficients
    # In this case, we use a simple linear combination of the x and y values
    return (polynomial_share.get((x, y), 0) + x + y) % 256  # Modulo to keep it in a manageable range

# Pre-Deployment Phase Simulation
def pre_deployment_phase():
    print("Starting Pre-Deployment Phase...\n")
    
    # Example inputs for CNj and IMDl
    CN_identity = "CN1"
    IMD_identity = "IMD1"
    N = random.randint(1000000000, 9999999999)  # Generate a random secret number N
    
    # Use current timestamp to ensure uniqueness
    timestamp = str(int(time.time()))
    
    # Step 1: T A selects a unique secret number N and computes pseudo identities
    RID_CN = compute_hash(CN_identity + str(N) + timestamp)  # Pseudo identity for CNj
    RID_IMD = compute_hash(IMD_identity + str(N) + timestamp)  # Pseudo identity for IMDl

    print(f"Pre-deployment Pseudo Identity for CNj: {RID_CN}")
    print(f"Pre-deployment Pseudo Identity for IMDl: {RID_IMD}")

    # Step 2: T A computes the polynomial shares for CNj and IMDl (preloaded in memory)
    degree = 4  # Example degree of the polynomial
    p = 5  # Example prime number (GF(p))

    # Simulate polynomial share generation based on random factors
    polynomial_share_CN = {}
    polynomial_share_IMD = {}

    for i in range(degree + 1):
        for j in range(degree + 1):
            polynomial_share_CN[(i, j)] = (i + j + random.randint(0, p-1)) % p
            polynomial_share_IMD[(i, j)] = (i * j + random.randint(0, p-1)) % p

    print(f"Polynomial share for CNj: {polynomial_share_CN}")
    print(f"Polynomial share for IMDl: {polynomial_share_IMD}\n")
    
    return RID_CN, RID_IMD, polynomial_share_CN, polynomial_share_IMD, N

# Post-Deployment Phase Simulation
def post_deployment_phase(RID_CN, RID_IMD, polynomial_share_CN, polynomial_share_IMD, N):
    print("Starting Post-Deployment Phase...\n")

    # Step 1: IMDl sends its pseudo identity RID_IMDl to CNj
    print(f"IMDl sends pseudo identity to CNj: RID_IMDl = {RID_IMD}")
    
    # Step 2: CNj sends its pseudo identity RID_CN to IMDl
    print(f"CNj sends pseudo identity to IMDl: RID_CN = {RID_CN}")

    # Step 3: IMDl computes the shared secret key using its own polynomial share
    SK_IMD_CN = evaluate_polynomial(polynomial_share_IMD, int(RID_IMD, 16), int(RID_CN, 16))
    print(f"IMDl computes shared secret key SK_IMD,CNj: {SK_IMD_CN}")

    # Step 4: CNj computes the shared secret key using its own polynomial share
    SK_CN_IMD = evaluate_polynomial(polynomial_share_CN, int(RID_CN, 16), int(RID_IMD, 16))
    print(f"CNj computes shared secret key SK_CN,IMDl: {SK_CN_IMD}")
    
    # Step 5: Verify that both computed keys are the same (since the polynomial is symmetric)
    if SK_IMD_CN == SK_CN_IMD:
        print("Shared secret key successfully established.\n")
    else:
        print("Error: Shared secret keys do not match.\n")

# Main pipeline that runs both the pre and post deployment phases
def main():
    # Step 1: Run Pre-Deployment Phase
    RID_CN, RID_IMD, polynomial_share_CN, polynomial_share_IMD, N = pre_deployment_phase()

    # Step 2: Run Post-Deployment Phase using the data from Pre-Deployment
    post_deployment_phase(RID_CN, RID_IMD, polynomial_share_CN, polynomial_share_IMD, N)

# Run the pipeline
if __name__ == "__main__":
    main()
