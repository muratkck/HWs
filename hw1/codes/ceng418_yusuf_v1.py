import random
import math
from sympy import isprime, mod_inverse
import time

def generate_prime(bit_length):
    """Generate a prime number of the specified bit length."""
    while True:
        # Generate a random number with the specified bit length
        if bit_length == 2:
            # 2-bit primes are only 2 and 3
            return random.choice([2, 3])
        
        # For other bit lengths, generate random numbers until a prime is found
        min_val = 2**(bit_length-1)
        max_val = 2**bit_length - 1
        candidate = random.randint(min_val, max_val)
        
        if isprime(candidate):
            return candidate

def gcd(a, b):
    """Calculate the greatest common divisor of two numbers."""
    while b:
        a, b = b, a % b
    return a

def generate_rsa_keys(bit_length):
    """Generate RSA key pair with primes of the specified bit length."""
    # Generate two distinct primes
    p = generate_prime(bit_length)
    q = generate_prime(bit_length)
    
    # Ensure p and q are different
    while p == q:
        q = generate_prime(bit_length)
    
    # Calculate n and Euler's totient function
    n = p * q
    phi_n = (p - 1) * (q - 1)
    
    # Special case for very small totients
    if phi_n <= 2:
        # For the extreme case where phi_n = 1 or 2, we'll make a compromise
        # Using e = 1 isn't standard in RSA but will work mathematically
        e = 1
    elif bit_length <= 4:
        # For small primes, find a suitable e
        potential_e_values = [e for e in range(3, phi_n, 2) if gcd(e, phi_n) == 1]
        if potential_e_values:
            e = random.choice(potential_e_values)
        else:
            # Fallback - check each odd number
            for e in range(3, phi_n, 2):
                if gcd(e, phi_n) == 1:
                    break
            else:  # This executes if the for loop completes without finding a value
                e = 1  # Last resort
    else:
        # Try standard e = 65537, if too large or not coprime with phi_n, find another
        e = 65537
        if e >= phi_n or gcd(e, phi_n) != 1:
            e = 3  # Start with a small prime
            while e < phi_n and gcd(e, phi_n) != 1:
                e += 2
            if e >= phi_n:  # If we couldn't find a suitable odd number
                e = 1
    
    # Calculate private exponent d
    # When e = 1, d will also be 1
    if e == 1:
        d = 1
    else:
        d = mod_inverse(e, phi_n)
    
    return (e, n), (d, n), p, q

def rsa_encrypt(message, public_key):
    """Encrypt a message using the RSA public key."""
    e, n = public_key
    # For simplicity, we'll encrypt each character separately
    encrypted = []
    for char in message:
        # Convert character to integer (ASCII value)
        m = ord(char)
        
        # Check if the message is smaller than n
        if m >= n:
            raise ValueError(f"Message character '{char}' (value {m}) is too large for n={n}. Try with larger bit length.")
        
        # Encrypt: c = m^e mod n
        c = pow(m, e, n)
        encrypted.append(c)
    
    return encrypted

def rsa_decrypt(encrypted, private_key):
    """Decrypt a message using the RSA private key."""
    d, n = private_key
    decrypted = ""
    for c in encrypted:
        # Decrypt: m = c^d mod n
        m = pow(c, d, n)
        # Convert integer back to character
        decrypted += chr(m)
    
    return decrypted

def simulate_brute_force(public_key, bit_length):
    """Simulate a brute force attack on RSA."""
    e, n = public_key
    
    start_time = time.time()
    
    # For demonstration, we'll just time how long it takes to factor n
    # In a real brute force attack, this would involve trying all possible factors
    
    # Instead of actually factoring, we'll simulate the time it would take
    # based on a simple model: checking all numbers up to sqrt(n)
    
    if bit_length <= 256:  # Actually perform factorization for small bit lengths
        factor_found = False
        
        for i in range(2, int(math.sqrt(n)) + 1):
            if n % i == 0:
                factor_found = True
                p = i
                q = n // i
                break
        
        end_time = time.time()
        duration = end_time - start_time
        
        if factor_found:
            return True, duration, (p, q)
        else:
            return False, duration, None
    else:
        # For larger bit lengths, we estimate the time (real attacks would take far longer)
        # This is just a simulation for demonstration purposes
        
        # Let's assume checking each potential factor takes 1 microsecond
        estimated_checks = math.sqrt(n)
        estimated_time = estimated_checks * 1e-6  # in seconds
        
        # We're not actually performing the attack, so return a placeholder
        return "Simulation", estimated_time, None

def demonstrate_rsa_with_bit_length(bit_length, message):
    """Demonstrate RSA encryption and decryption with specified bit length."""
    print(f"\n{'='*80}")
    print(f"RSA WITH {bit_length}-BIT PRIMES")
    print(f"{'='*80}")
    
    try:
        # Generate keys
        print("Generating RSA keys...")
        public_key, private_key, p, q = generate_rsa_keys(bit_length)
        e, n = public_key
        d, _ = private_key
        
        print(f"Prime p: {p}")
        print(f"Prime q: {q}")
        print(f"Modulus n = p*q: {n}")
        print(f"Public exponent e: {e}")
        print(f"Private exponent d: {d}")
        
        # Encrypt message
        print(f"\nEncrypting message: '{message}'")
        try:
            encrypted = rsa_encrypt(message, public_key)
            print(f"Encrypted (decimal): {encrypted}")
            
            # Decrypt message
            decrypted = rsa_decrypt(encrypted, private_key)
            print(f"Decrypted: '{decrypted}'")
            
            # Simulate brute force attack
            print("\nSimulating brute force attack...")
            result, duration, factors = simulate_brute_force(public_key, bit_length)
            
            if result is True:
                print(f"Attack successful! Factors found: p={factors[0]}, q={factors[1]}")
                print(f"Time taken: {duration:.6f} seconds")
            elif result == "Simulation":
                print(f"Attack simulated. Estimated time: {duration:.2e} seconds " +
                      f"({duration/60:.2e} minutes, {duration/3600:.2e} hours, {duration/86400:.2e} days)")
                print("Note: Actual time would vary based on hardware and optimization.")
            else:
                print(f"Attack unsuccessful after {duration:.6f} seconds")
        
        except ValueError as e:
            print(f"Error: {e}")
    
    except Exception as e:
        print(f"Failed to generate keys or perform operations: {e}")

def main():
    message = "Hello, RSA!"
    
    bit_lengths = [2, 4, 8, 16, 32, 64, 128, 256]
    
    for bit_length in bit_lengths:
        demonstrate_rsa_with_bit_length(bit_length, message)

if __name__ == "__main__":
    main()
 
