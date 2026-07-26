import json
import requests
import hashlib
import time

INPUT_JSON = "raw_transactions.json"
API_URLS = [
    "https://blockstream.info{}/hex",
    "https://mempool.space{}/hex",
    "https://blockchain.info{}?format=hex"
]

def decode_der_signature(sig_hex):
    try:
        sig_bytes = bytes.fromhex(sig_hex)
        if sig_bytes[0] != 0x30: return None, None
        if sig_bytes[2] != 0x02: return None, None
        r_length = sig_bytes[3]
        r_bytes = sig_bytes[4:4+r_length]
        
        s_marker_idx = 4 + r_length
        if sig_bytes[s_marker_idx] != 0x02: return None, None
        s_length = sig_bytes[s_marker_idx + 1]
        s_bytes = sig_bytes[s_marker_idx + 2 : s_marker_idx + 2 + s_length]
        
        if len(r_bytes) > 32 and r_bytes[0] == 0x00: r_bytes = r_bytes[1:]
        if len(s_bytes) > 32 and s_bytes[0] == 0x00: s_bytes = s_bytes[1:]
        
        return r_bytes.hex().zfill(64), s_bytes.hex().zfill(64)
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
        return hashlib.sha256(hashlib.sha256(b).digest()).hexdigest()
    except:
        return None

def main():
    try:
        with open(INPUT_JSON, 'r') as file:
            data = json.load(file)
    except Exception as e:
        print(f"Error: {e}")
        return

    # Dictionary to keep track of where each R value was seen
    # Structure: { r_value: [(txid, input_index, z_value, s_value), ...] }
    r_registry = {}

    print("Analyzing all transactions for signature vulnerabilities...")

    for address, tx_list in data.items():
        for tx in tx_list:
            txid = tx.get("txid")
            raw_hex = fetch_raw_hex(txid)
            if not raw_hex: continue
            
            z_val = calculate_z(raw_hex)
            if not z_val: continue

            for idx, vin in enumerate(tx.get("vin", [])):
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
                        if r not in r_registry:
                            r_registry[r] = []
                        r_registry[r].append((txid, idx, z_val, s))
            time.sleep(0.2)

    # Evaluate results
    vulnerabilities_found = False
    print("\n" + "="*50)
    print("VULNERABILITY REPORT RESULTS")
    print("="*50)

    for r_value, occurrences in r_registry.items():
        if len(occurrences) > 1:
            # Check if they are actually different messages (Z values)
            unique_z_values = set(item[2] for item in occurrences)
            if len(unique_z_values) > 1:
                vulnerabilities_found = True
                print(f"\n🚨 CRITICAL: Reused R-Value Detected! (Nonce Leakage)")
                print(f"  R = {r_value}")
                for occ in occurrences:
                    print(f"  Seen in TX: {occ[0]} (Input {occ[1]})")
                    print(f"    Z = {occ[2]}")
                    print(f"    S = {occ[3]}")

    if not vulnerabilities_found:
        print("\n✅ Clean! No reused R-values or critical signature leaks detected.")
        print(f"Scanned {len(r_registry)} unique cryptographic R-signatures.")

if __name__ == "__main__":
    main()
