import hashlib
import random

class TrustedAuthority:
    def __init__(self, prime_field):
        self.prime_field = prime_field  # A large prime number for GF(p)

    def hash_function(self, input_string):
        """Generate a hash value for the given input."""
        return int(hashlib.sha256(input_string.encode()).hexdigest(), 16)

    def generate_unique_id(self, existing_ids):
        """Generate a unique ID not in the existing IDs."""
        while True:
            new_id = f"CN{random.randint(1000, 9999)}"
            if new_id not in existing_ids:
                return new_id

    def compute_rid(self, unique_id, nonce):
        """Compute the pseudo identity RID."""
        return self.hash_function(f"{unique_id}||{nonce}")

    def compute_tc(self, ta_id, rts, nonce):
        """Compute the temporal credential T_C."""
        return self.hash_function(f"{ta_id}||{rts}||{nonce}")

    def generate_polynomial_share(self, rid, degree=2):
        """Generate a polynomial share in GF(p)."""
        coefficients = [random.randint(1, self.prime_field - 1) for _ in range(degree)]
        return lambda x: sum(c * (x ** i) % self.prime_field for i, c in enumerate(coefficients)) % self.prime_field

    def add_controller_node(self, ta_id, existing_ids, nonce):
        """Perform the dynamic controller node addition steps."""
        # Step 1: Assign a new unique ID and compute credentials
        unique_id = self.generate_unique_id(existing_ids)
        rid = self.compute_rid(unique_id, nonce)
        rts = random.randint(1, 10**6)  # Registration timestamp
        tc = self.compute_tc(ta_id, rts, nonce)
        
        # Generate polynomial share
        polynomial_share = self.generate_polynomial_share(rid)

        # Credentials to store in the new node
        credentials = {
            "RID": rid,
            "T_C": tc,
            "RID_TA": self.compute_rid(ta_id, nonce),
            "P_share": polynomial_share(rid)
        }

        return unique_id, credentials

# Example usage
prime_field = 104729  # Example prime number 
ta = TrustedAuthority(prime_field)
existing_ids = {"CN1001", "CN1002", "CN1003"}
ta_id = "TA123"
nonce = random.randint(1, 10**6)

unique_id, credentials = ta.add_controller_node(ta_id, existing_ids, nonce)

print("New Controller Node ID:", unique_id)
print("Stored Credentials:")
for key, value in credentials.items():
    print(f"  {key}: {value}")
