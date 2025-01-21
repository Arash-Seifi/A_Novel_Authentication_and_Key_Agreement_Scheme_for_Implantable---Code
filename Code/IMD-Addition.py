import hashlib
from typing import Callable

def hash_function(input_data: str) -> str:
    return hashlib.sha256(input_data.encode()).hexdigest()

def generate_polynomial(rid: str, y: int) -> Callable[[int], int]:
    def polynomial(x: int) -> int:
        # Example polynomial P(x, y) = x^2 + y*x + hash_value_as_int
        hash_value_as_int = int(rid[:8], 16)  # Use a portion of the hash for simplicity
        return x**2 + y * x + hash_value_as_int
    
    return polynomial

def dynamic_imd_addition(ta_id: str, n: int, y: int):
    # Step 1: Generate unique identity and pseudo identity
    id_imd = ta_id
    rid_imd = hash_function(f"{id_imd}||{n}")

    # Compute the polynomial share
    polynomial = generate_polynomial(rid_imd, y)

    # Save the polynomial and RID (simulated as return values)
    polynomial_share = {"RID": rid_imd, "polynomial": polynomial}

    print(f"RID for IMD {ta_id}: {rid_imd}")
    print("Polynomial share computed.")

    # Example pairwise key establishment
    def compute_secure_key(rid_cnj: str):
        return polynomial(int(rid_cnj[:8], 16))  # Simplified example

    # Return the results
    return {
        "RID_IMD": rid_imd,
        "Polynomial_Share": polynomial,
        "Secure_Key_Function": compute_secure_key,
    }

# Example usage
if __name__ == "__main__":
    ta_id = "IMD_1"
    n = 12345  # Example unique identifier
    y = 5      # Example parameter for polynomial

    result = dynamic_imd_addition(ta_id, n, y)

    # Example of establishing a secure key with CNj
    rid_cnj = hash_function("CNj||67890")
    secure_key = result["Secure_Key_Function"](rid_cnj)
    print(f"Secure key established with CNj: {secure_key}")
