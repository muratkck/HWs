import random
import time
import matplotlib.pyplot as plt
from sympy import isprime
import math
from tabulate import tabulate
import numpy as np
from scipy.optimize import curve_fit

def generate_prime(bits):
    print(f"[+] Generating a {bits}-bit prime...")
    while True:
        p = random.getrandbits(bits)
        if isprime(p):
            print(f"    -> Prime found: {p}")
            return p

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def mod_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def generate_rsa_keys(bits):
    """Generate RSA key pair using primes of specified bit length."""
    print(f"[+] Generating RSA keys using {bits}-bit primes...")
    # Generate two distinct primes
    p = generate_prime(bits)
    q = generate_prime(bits)
    
    # Ensure p and q are different
    max_attempts = 20
    attempts = 0
    while p == q and attempts < max_attempts:
        print(f"    -> Duplicated primes, regenerating q...")
        q = generate_prime(bits)
        attempts += 1
    
    if p == q:
        raise ValueError(f"Could not generate distinct primes after {max_attempts} attempts")
    
    # Calculate n and totient
    n = p * q
    phi = (p - 1) * (q - 1)
    
    # Find e such that gcd(e, phi) = 1
    # For very small bit lengths, phi might be too small
    if phi <= 2:
        # For extremely small totients, use a fixed approach
        e = 1  # This is a special case for very small numbers
        d = 1
    else:
        # Normal case
        e = random.randint(2, phi - 1)
        while math.gcd(e, phi) != 1:
            e = random.randint(2, phi - 1)
        
        # Calculate d (modular multiplicative inverse)
        d = pow(e, -1, phi)
    
    public_key = (e, n)
    private_key = (d, n)
    
    return public_key, private_key

def encrypt_message(message, public_key):
    """Encrypt a message using RSA public key."""
    e, n = public_key
    # Convert message to integer (ASCII value)
    m = ord(message[0]) if isinstance(message, str) else message
    
    # Check if message is too large for the modulus
    if m >= n:
        print(f"    -> Warning: Message value {m} is >= modulus {n}")
        print(f"    -> Message will be taken as {m % n} (modulo n)")
        m = m % n
    
    # Encrypt: c = m^e mod n
    c = pow(m, e, n)
    print(f"[+] Encrypting message '{message}' to integer {m}")
    print(f"    -> Ciphertext: {c}")
    return c

def brute_force_decrypt(ciphertext, public_key):
    """Attempt to find the message by trying all possible values."""
    e, n = public_key
    print(f"[!] Starting brute-force decryption...")
    
    start_time = time.time()
    original_value = None
    
    for m in range(n):  # Try all possible messages less than n
        if pow(m, e, n) == ciphertext:
            original_value = m
            break
    
    elapsed = time.time() - start_time
    return original_value, elapsed

def test_rsa_with_bit_length(bits, message='A'):
    """Test RSA with specified bit length and measure brute force time."""
    print("\n" + "="*50)
    print(f"[*] Testing {bits}-bit RSA key pair")
    
    # Generate key pair
    public_key, private_key = generate_rsa_keys(bits)
    e, n = public_key
    d, n = private_key
    
    # Encrypt message
    cipher = encrypt_message(message, public_key)
    
    # Decrypt with brute force
    decrypted_value, elapsed = brute_force_decrypt(cipher, public_key)
    
    if decrypted_value is not None:
        # Check if we need to map back to the original ASCII value
        if decrypted_value < 128 and chr(decrypted_value) == message:
            # Direct match with ASCII
            print(f"[✓] Found message: {decrypted_value} ('{chr(decrypted_value)}') in {elapsed:.4f} seconds")
        else:
            # Recovered the encrypted value, but it's not the original ASCII
            print(f"[✓] Found encrypted value: {decrypted_value} in {elapsed:.4f} seconds")
            print(f"    -> Note: This is the correct encrypted value, but due to small modulus,")
            print(f"       it's not the original ASCII value of '{message}' (which is {ord(message)})")
    else:
        print(f"[✗] Brute-force failed to find message in {elapsed:.4f} seconds")
    
    print(f"[✓] Brute-force completed in {elapsed:.4f} seconds for {bits}-bit keys")
    
    return elapsed

def plot_and_save_results(bit_lengths, times):
    """Plot the brute force times and save the results to files."""
    plt.figure(figsize=(10, 6))
    
    # Create the plot
    plt.plot(bit_lengths, times, 'o-', linewidth=2, markersize=8)
    plt.title('RSA Brute Force Attack Time vs Key Size', fontsize=16)
    plt.xlabel('Key Size (bits)', fontsize=14)
    plt.ylabel('Time (seconds)', fontsize=14)
    plt.grid(True)
    
    # Set x-ticks to match our bit lengths
    plt.xticks(bit_lengths)
    
    # Add annotations for each point
    for i, (bits, t) in enumerate(zip(bit_lengths, times)):
        plt.annotate(f"{t:.4f}s", 
                     (bits, t),
                     textcoords="offset points", 
                     xytext=(0,10), 
                     ha='center')
    
    # Use log scale for y-axis if the times span several orders of magnitude
    if max(times) / (min(times) + 1e-10) > 100:  # Add small value to avoid division by zero
        plt.yscale('log')
        plt.ylabel('Time (seconds, log scale)', fontsize=14)
    
    # Save the figure
    plt.tight_layout()
    plt.savefig('rsa_brute_force_times.png', dpi=300)
    print(f"[✓] Plot saved as 'rsa_brute_force_times.png'")
    
    # Also save the data as a table in a text file
    with open('rsa_brute_force_results.txt', 'w') as f:
        table_data = [[bits, f"{time:.6f} seconds"] for bits, time in zip(bit_lengths, times)]
        f.write("RSA Brute Force Attack Times\n")
        f.write("============================\n\n")
        f.write(tabulate(table_data, headers=["Bit Length", "Time (seconds)"], tablefmt="grid"))
        
        # Calculate time ratios between consecutive bit lengths
        f.write("\n\nTime Ratios (showing exponential growth):\n")
        f.write("=======================================\n\n")
        ratios = []
        for i in range(1, len(times)):
            ratio = times[i] / max(times[i-1], 1e-10)  # Avoid division by zero
            ratios.append([f"{bit_lengths[i-1]} to {bit_lengths[i]}", f"{ratio:.2f}x"])
        
        f.write(tabulate(ratios, headers=["Bit Length Increase", "Time Ratio"], tablefmt="grid"))
    
    print(f"[✓] Detailed results saved as 'rsa_brute_force_results.txt'")

def estimate_supercomputer_cracking_time(bit_lengths, times):
    """
    Estimate the time it would take for a supercomputer to crack a 256-bit RSA key
    based on your local machine's performance.
    """
    # Choose a supercomputer for comparison
    supercomputer = {
        "name": "Frontier (ORNL)",
        "peak_performance": 1.102e18,  # FLOPS (floating-point operations per second)
        "cores": 8699904,  # CPU cores
        "memory": "700 TB",
        "year": 2022,
        "location": "Oak Ridge National Laboratory, USA"
    }
    
    # Estimate your local machine's performance (typical high-end desktop/laptop)
    local_machine_flops = 5e9  # ~5 GFLOPS for a typical modern CPU core
    
    # Calculate speedup factor
    speedup_factor = supercomputer["peak_performance"] / local_machine_flops
    
    # Fit an exponential model to your measured times
    # log(time) = a + b*bits is equivalent to time = e^a * e^(b*bits)
    
    # Function to fit: time = A * 2^(B*bits)
    def exp_func(x, a, b):
        return a * np.power(2, b * x)
    
    # For fitting, we need to exclude any zero times
    valid_indices = [i for i, t in enumerate(times) if t > 0]
    valid_bits = [bit_lengths[i] for i in valid_indices]
    valid_times = [times[i] for i in valid_indices]
    
    # If we have enough data points, fit the curve
    if len(valid_times) >= 3:
        try:
            popt, _ = curve_fit(exp_func, valid_bits, valid_times, p0=[1e-10, 0.5], maxfev=10000)
            a, b = popt
            
            # Calculate estimated time for 256-bit RSA on local machine
            local_time_256bit = exp_func(256, a, b)  # seconds
            
            # Calculate the time for the supercomputer
            supercomputer_time_256bit = local_time_256bit / speedup_factor  # seconds
        except Exception as e:
            print(f"[!] Error fitting curve: {e}")
            # Fallback: Use simple extrapolation based on the ratio of the largest bit size
            largest_bit = max(valid_bits)
            largest_time = times[bit_lengths.index(largest_bit)]
            
            # RSA complexity grows exponentially with bit size
            factor = 2 ** (256 - largest_bit)
            local_time_256bit = largest_time * factor
            supercomputer_time_256bit = local_time_256bit / speedup_factor
    else:
        # Not enough data points, use simple extrapolation
        largest_bit = max(bit_lengths[:len(times)])
        largest_time = times[-1]
        
        # RSA complexity grows exponentially with bit size
        factor = 2 ** (256 - largest_bit)
        local_time_256bit = largest_time * factor
        supercomputer_time_256bit = local_time_256bit / speedup_factor
    
    # Format the times in appropriate units
    def format_time(seconds):
        if seconds < 60:
            return f"{seconds:.2f} seconds"
        elif seconds < 3600:
            return f"{seconds/60:.2f} minutes"
        elif seconds < 86400:
            return f"{seconds/3600:.2f} hours"
        elif seconds < 86400*365:
            return f"{seconds/86400:.2f} days"
        elif seconds < 86400*365*100:
            return f"{seconds/(86400*365):.2f} years"
        elif seconds < 86400*365*1000:
            return f"{seconds/(86400*365):.2e} years"
        else:
            return f"{seconds/(86400*365):.2e} years (universe age is ~13.8 billion years)"
    
    # Write results to a file
    with open('supercomputer_comparison.txt', 'w') as f:
        f.write("Estimating Time to Crack 256-bit RSA\n")
        f.write("===================================\n\n")
        
        f.write("Supercomputer Specifications:\n")
        f.write(f"  Name: {supercomputer['name']}\n")
        f.write(f"  Peak Performance: {supercomputer['peak_performance']:.2e} FLOPS\n")
        f.write(f"  CPU Cores: {supercomputer['cores']:,}\n")
        f.write(f"  Memory: {supercomputer['memory']}\n")
        f.write(f"  Year: {supercomputer['year']}\n")
        f.write(f"  Location: {supercomputer['location']}\n\n")
        
        f.write("Cracking Time Estimates:\n")
        f.write(f"  Your Machine: {format_time(local_time_256bit)}\n")
        f.write(f"  {supercomputer['name']}: {format_time(supercomputer_time_256bit)}\n\n")
        
        f.write("Speed-up Factor:\n")
        f.write(f"  {supercomputer['name']} is approximately {speedup_factor:.2e} times faster than your machine\n\n")
        
        # Add context on the security implications
        f.write("Security Context:\n")
        if supercomputer_time_256bit < 86400*365*100:  # If less than 100 years
            f.write("  WARNING: This key size might be vulnerable to a determined attacker with access\n")
            f.write("  to supercomputing resources. Modern RSA implementations typically use 2048-bit\n")
            f.write("  or 4096-bit keys to ensure long-term security.\n")
        else:
            f.write("  Even with a leading supercomputer, breaking this 256-bit RSA key would take an\n")
            f.write("  astronomical amount of time, making it computationally secure against brute force.\n")
            f.write("  However, typical RSA implementations use 2048-bit or 4096-bit keys to protect\n")
            f.write("  against future computing advances and mathematical breakthroughs.\n")
            
        # Add note about quantum computing
        f.write("\nNote on Quantum Computing:\n")
        f.write("  Quantum computers using Shor's algorithm could theoretically break RSA encryption\n")
        f.write("  much faster. A sufficiently powerful quantum computer could factor an RSA-256 key\n")
        f.write("  in seconds to minutes. However, current quantum computers are not yet capable of\n")
        f.write("  breaking RSA keys of any practical size.\n")
    
    print(f"[✓] Supercomputer comparison results saved as 'supercomputer_comparison.txt'")
    
    return {
        "local_time": local_time_256bit,
        "supercomputer_time": supercomputer_time_256bit,
        "speedup_factor": speedup_factor,
        "supercomputer": supercomputer
    }

# Test for various bit lengths
bit_lengths = [2, 4, 8, 16, 32, 64, 128, 256, 512]
brute_force_times = []

for bits in bit_lengths:
    print("="*50)
    print(f"[*] Testing {bits}-bit RSA key pair")
    pub, priv = generate_rsa_keys(bits)
    cipher = encrypt_message("A", pub)
    message, elapsed = brute_force_decrypt(cipher, pub)
    if message is not None:
        print(f"[✓] Found message: {message} ('{chr(message)}') in {elapsed:.4f} seconds")
    else:
        print(f"[✗] Brute-force failed to find correct message in {elapsed:.4f} seconds")
    brute_force_times.append(elapsed)
    print(f"[✓] Brute-force completed in {elapsed:.4f} seconds for {bits}-bit keys\n")

plot_and_save_results(bit_lengths, brute_force_times)
estimate_supercomputer_cracking_time(bit_lengths, brute_force_times)
