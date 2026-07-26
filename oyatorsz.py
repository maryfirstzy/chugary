import json
import requests
import hashlib
import time

INPUT_JSON = "raw_transactions.json"

# List of public endpoints to fetch transaction hex strings
API_URLS = [
    "https://blockstream.info/api/tx/{}/hex",
    "https://mempool.space/api/tx/{}/hex",
    "https://blockchain.info/rawtx/{}?format=hex"
]

def decode_der_signature(sig_hex):
    """Parses a hexadecimal DER-encoded ECDSA signature to extract R and S."""
    try:
        sig_bytes = bytes.fromhex(sig_hex)
        if sig_bytes[0] != 0x30:
            return None, None
        
        # Extract R
        if sig_bytes[2] != 0x02:
            return None, None
        r_length = sig_bytes[3]
        r_start = 4
        r_end = r_start + r_length
        r_bytes = sig_bytes[r_start:r_end]
        
        # Extract S
        if sig_bytes[r_end] != 0x02:
            return None, None
        s_length = sig_bytes[r_end + 1]
        s_start = r_end + 2
        s_end = s_start + s_length
        s_bytes = sig_bytes[s_start:s_end]
        
        # Clean up leading DER sign padding bytes
        if len(r_bytes) > 32 and r_bytes[0] == 0x00: r_bytes = r_bytes[1:]
        if len(s_bytes) > 32 and s_bytes[0] == 0x00: s_bytes = s_bytes[1:]
        
        return r_bytes.hex().zfill(64), s_bytes.hex().zfill(64)
    except Exception:
        return None, None

def fetch_raw_tx_hex_with_fallback(txid):
    """Tries multiple public APIs to fetch the complete transaction hex string."""
    for url_template in API_URLS:
        url = url_template.format(txid)
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200 and len(response.text.strip()) > 60:
                return response.text.strip()
        except Exception:
            continue
        time.sleep(0.5) # Quick pause before checking fallback provider
    return None

def calculate_approx_z(raw_tx_hex):
    """
    Computes the standardized Double-SHA256 signature message hash baseline (Z)
    from the raw immutable binary string.
    """
    try:
        tx_bytes = bytes.fromhex(raw_tx_hex)
        first_hash = hashlib.sha256(tx_bytes).digest()
        second_hash = hashlib.sha256(first_hash).digest()
        return second_hash.hex()
    except Exception:
        return "Reconstruction Error"

def main():
    try:
        with open(INPUT_JSON, 'r') as file:
            data = json.load(file)
    except Exception as e:
        print(f"Error loading {INPUT_JSON}: {e}")
        return

    for address, tx_list in data.items():
        print(f"\n" + "="*60)
        print(f"PROCESSING EXTRACTION FOR ADDRESS: {address}")
        print("="*60)

        for tx in tx_list:
            txid = tx.get("txid")
            print(f"\n[TXID]: {txid}")
            
            raw_hex = fetch_raw_tx_hex_with_fallback(txid)
            if not raw_hex:
                print("  ❌ Failed to download transaction raw binary after checking all fallback APIs.")
                continue

            z_hash = calculate_approx_z(raw_hex)

            for idx, vin in enumerate(tx.get("vin", [])):
                script_asm = vin.get("scriptsig_asm", "")
                witness = vin.get("witness", [])
                
                sig_hex = None
                
                # Check Legacy script blocks
                if "OP_PUSHBYTES" in script_asm:
                    for part in script_asm.split():
                        if 140 <= len(part) <= 146:
                            sig_hex = part
                            break
                            
                # Check SegWit witness arrays
                if not sig_hex and witness:
                    for item in witness:
                        if 140 <= len(item) <= 146:
                            sig_hex = item
                            break
                
                if sig_hex:
                    der_sig = sig_hex[:-2]
                    sighash_type = sig_hex[-2:]
                    
                    r, s = decode_der_signature(der_sig)
                    
                    if r and s:
                        print(f"  Input [{idx}]:")
                        print(f"    R = {r}")
                        print(f"    S = {s}")
                        print(f"    Z = {z_hash}")
                        print(f"    Sighash = {sighash_type}")
                    else:
                        print(f"  Input [{idx}]: Could not decode cryptographic DER format alignment.")
                else:
                    print(f"  Input [{idx}]: No valid signature script found.")
            
            time.sleep(1) # General rate limit protection

if __name__ == "__main__":
    main()
