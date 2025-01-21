import hashlib

# Define hash function h
def h(data):
    return hashlib.sha256(data.encode()).hexdigest()

# Define the Rep function to extract biometric key (mock implementation)
def Rep(biometrics, tau):
    # This is a mock implementation. Replace with the actual biometric processing.
    return hashlib.sha256(biometrics.encode()).hexdigest()

def update_password_and_biometrics(user_data, IDi, PWold_i, BIOold_i, PWnew_i, BIOnew_i=None):
    # Extract user data
    Di = user_data['Di']
    Ai = user_data['Ai']
    Ci = user_data['Ci']
    RID_TA = user_data['RID_TA']
    RID_i = user_data['RID_i']
    tau_i = user_data['tau_i']

    # Ensure all input strings are valid hexadecimal
    try:
        int(Di, 16)
        int(Ai, 16)
        int(RID_TA, 16)
        int(RID_i, 16)
    except ValueError as e:
        print(f"Invalid hexadecimal string: {e}")
        return False

    # Step PB1
    sigma_old_i = Rep(BIOold_i, tau_i)
    k = int(Di, 16) ^ int(h(IDi + PWold_i + sigma_old_i), 16)
    RPWold_i = h(PWold_i + str(k))
    Aold_i = int(Ai, 16) ^ int(h(str(k) + sigma_old_i), 16)
    Bold_i = h(str(Aold_i) + RPWold_i)
    RID_TA_old = int(RID_TA, 16) ^ int(h(IDi + str(k) + sigma_old_i), 16)
    RID_i_old = int(RID_i, 16) ^ int(h(PWold_i + sigma_old_i), 16)
    Cold_i = h(IDi + str(RID_TA_old) + Bold_i + sigma_old_i)


    # Verify old credentials
    if Cold_i != Ci:
        print("Password and biometric verification failed.")
        return False

    # Step PB2
    if BIOnew_i is None:
        BIOnew_i = BIOold_i
    sigma_new_i = Rep(BIOnew_i, tau_i)
    RPWnew_i = h(PWnew_i + str(k))
    Anew_i = Aold_i ^ int(h(str(k) + sigma_new_i), 16)
    Bnew_i = h(str(Anew_i) + RPWnew_i)
    RID_TA_new = RID_TA_old ^ int(h(IDi + str(k) + sigma_new_i), 16)
    RID_i_new = RID_i_old ^ int(h(PWnew_i + sigma_new_i), 16)
    Cnew_i = h(IDi + str(RID_TA_new) + Bnew_i + sigma_new_i)
    Dnew_i = k ^ int(h(IDi + PWnew_i + sigma_new_i), 16)

    # Step PB3
    user_data['RID_i'] = hex(RID_i_new)[2:]
    user_data['RID_TA'] = hex(RID_TA_new)[2:]
    user_data['Ai'] = hex(Anew_i)[2:]
    user_data['Ci'] = Cnew_i
    user_data['Di'] = hex(Dnew_i)[2:]
    user_data['tau_i'] = tau_i  # Assuming tau_i is updated
    print("Password and biometric update is successful.")
    return True

# Example usage with valid hexadecimal strings
# Replace 'some_hash_value' with the actual stored Ci value that matches the initial conditions.
user_data = {
    'Di': '0abc123',
    'Ai': '0def456',
    'Ci': '9df7a09ff9c4f43629bb819a287665831ae215bbd32eeadd84c53397bdbe539a',  # Replace with actual stored value
    'RID_TA': '0123456789abcdef',
    'RID_i': 'abcdef0123456789',
    'tau_i': 'tau_value'
}

IDi = 'user123'
PWold_i = 'old_password'
BIOold_i = 'old_biometrics'
PWnew_i = 'new_password'
BIOnew_i = 'new_biometrics'

update_password_and_biometrics(user_data, IDi, PWold_i, BIOold_i, PWnew_i, BIOnew_i)