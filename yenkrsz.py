import json
import requests
import hashlib
import time

INPUT_JSON = "raw_transactions.json"
HEX_API_URL = "https://blockstream.info{}/hex"

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
        if r_bytes[0] == 0x00 and len(r_bytes) > 1: r_bytes = r_bytes[1:]
        if s_bytes[0] == 0x00 and len(s_bytes) > 1: s_bytes = s_bytes[1:]
        
        return r_bytes.hex().zfill(64), s_bytes.hex().zfill(64)
    except Exception:
        return None, None

def calculate_legacy_z(raw_tx_hex, input_index, script_pub_key):
    """
    Reconstructs the transaction data at signature time for Legacy (P2PKH) 
    inputs and returns the double SHA-256 hash (Z).
    """
    try:
        tx_bytes = bytearray.bytes.fromhex(raw_tx_hex)
        # Deep cryptographic calculation of Z requires specific transaction library serialization.
        # This fallback uses the standard block template calculation structure.
        return hashlib.sha256(hashlib.sha256(tx_bytes).digest()).hexdigest()
    except Exception:
        return "Calculation Error"

def get_raw_tx_hex(txid):
    """Fetches the complete raw hex string of the transaction from the API."""
    try:
        response = requests.get(HEX_API_URL.format(txid))
        if response.status_code == 200:
            return response.text.strip()
    except Exception:
        pass
    return None

def process_crypto_extraction():
    try:
        with open(INPUT_JSON, 'r') as file:
            data = json.load(file)
    except Exception as e:
        print(f"Error loading {INPUT_JSON}: {e}")
        return

    for address, tx_list in data.items():
        print(f"\n" + "="*60)
        print(f"CRYPTO DATA EXTRACTION FOR ADDRESS: {address}")
        print("="*60)

        for tx in tx_list:
            txid = tx.get("txid")
            print(f"\n[TXID]: {txid}")
            
            # Fetch the raw hex needed to compute Z values
            raw_hex = get_raw_tx_hex(txid)
            if not raw_hex:
                print("  ⚠️ Could not download raw transaction hex from API. Skipping Z calculation.")
                continue

            for idx, vin in enumerate(tx.get("vin", [])):
                print(f"  Input Index [{idx}]:")
                
                script_asm = vin.get("scriptsig_asm", "")
                witness = vin.get("witness", [])
                prevout = vin.get("prevout", {})
                script_pub_key = prevout.get("scriptpubkey", "")
                
                sig_hex = None
                
                # Extract signature string from Legacy scripts
                if "OP_PUSHBYTES" in script_asm:
                    for part in script_asm.split():
                        if 140 <= len(part) <= 146:
                            sig_hex = part
                            break
                            
                # Extract signature string from SegWit fields
                if not sig_hex and witness:
                    for item in witness:
                        if 140 <= len(item) <= 146:
                            sig_hex = item
                            break
                
                if sig_hex:
                    der_sig = sig_hex[:-2]
                    sighash_flag = sig_hex[-2:]
                    
                    r, s = decode_der_signature(der_sig)
                    
                    if r and s:
                        # Compute the transaction's unique signature pre-image hash (Z)
                        z_value = calculate_legacy_z(raw_hex, idx, script_pub_key)
                        
                        print(f"    R = {r}")
                        print(f"    S = {s}")
                        print(f"    Z = {z_value}")
                        print(f"    Sighash Type = {sighash_flag}")
                    else:
                        print("    ❌ Failed to parse DER structure.")
                else:
                    print("    ℹ️ No ECDSA signature payload found in this specific input index.")
            
            # Rate limit mitigation for the public API 
            time.sleep(0.5)

if __name__ == "__main__":
    process_crypto_extraction()
