import json
import requests
import hashlib
import time

INPUT_FILE = "BTC.txt"
# Multi-API redundancy list for finding raw hex vectors
HEX_API_URLS = [
    "https://blockstream.info{}/hex",
    "https://mempool.space{}/hex",
    "https://blockchain.info{}?format=hex"
]
TX_HISTORY_API = "https://blockstream.info{}/txs"

def get_transactions_for_address(address):
    """Fetches the transaction history payload for a specific address."""
    try:
        response = requests.get(TX_HISTORY_API.format(address), timeout=10)
        if response.status_code == 200:
            return response.json()
    except Exception as e:
        print(f"Error checking history for {address}: {e}")
    return []

def fetch_raw_hex(txid):
    """Tries fallback servers to grab the complete machine-code hex of a transaction."""
    for url_template in HEX_API_URLS:
        try:
            res = requests.get(url_template.format(txid), timeout=8)
            if res.status_code == 200 and len(res.text.strip()) > 60:
                return res.text.strip()
        except:
            continue
    return None

def calculate_z(raw_hex):
    """Computes the double-SHA256 signature message hash (Z)."""
    try:
        b = bytes.fromhex(raw_hex)
        h = hashlib.sha256(hashlib.sha256(b).digest()).hexdigest()
        return int(h, 16)
    except:
        return None

def decode_der_signature_and_pubkey(script_asm, witness):
    """Parses input script structures to pull out R, S, and the Public Key."""
    try:
        sig_hex = None
        pubkey_hex = None
        
        # Scenario A: Legacy P2PKH script sig blocks
        if "OP_PUSHBYTES" in script_asm:
            tokens = script_asm.split()
            for t in tokens:
                if 140 <= len(t) <= 146:
                    sig_hex = t
                elif len(t) in: # FIXED: Added valid hex string lengths
                    pubkey_hex = t
                    
        # Scenario B: SegWit Witness vector stack
        if not sig_hex and witness:
            for item in witness:
                if 140 <= len(item) <= 146:
                    sig_hex = item
                elif len(item) in: # FIXED: Added valid hex string lengths
                    pubkey_hex = item

        if not sig_hex:
            return None, None, None, None

        # Process and unpack DER signature bytes (removing the 1-byte Sighash flag)
        sig_bytes = bytes.fromhex(sig_hex[:-2])
        if sig_bytes[0] != 0x30: return None, None, None, None
        
        r_len = sig_bytes[1]
        r_bytes = sig_bytes[4 : 4 + r_len]
        
        s_marker = 4 + r_len
        if sig_bytes[s_marker] != 0x02: return None, None, None, None
        s_len = sig_bytes[s_marker + 1]
        s_bytes = sig_bytes[s_marker + 2 : s_marker + 2 + s_len]
        
        return int(r_bytes.hex(), 16), int(s_bytes.hex(), 16), pubkey_hex, sig_hex[-2:]
    except Exception:
        return None, None, None, None

def main():
    try:
        with open(INPUT_FILE, 'r') as file:
            addresses = [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print(f"❌ Error: {INPUT_FILE} not found. Please create it first.")
        return

    print(f"📖 Loaded {len(addresses)} address(es) from {INPUT_FILE}. Commencing matrix processing...")

    for address in addresses:
        print("\n" + "="*70)
        print(f"🔍 SCANNING ADDRESS: {address}")
        print("="*70)
        
        tx_list = get_transactions_for_address(address)
        if not tx_list:
            print("  ℹ️ No transaction history found on the public chain for this address.")
            continue

        valid_signatures = 0

        for tx in tx_list:
            txid = tx.get("txid")
            
            # Loop through inputs to locate elements belonging to the target address
            for idx, vin in enumerate(tx.get("vin", [])):
                if vin.get("prevout", {}).get("scriptpubkey_address", "") != address:
                    continue
                
                # Public key is only found in spent inputs. Let's process it.
                raw_hex = fetch_raw_hex(txid)
                if not raw_hex:
                    continue
                    
                z_val = calculate_z(raw_hex)
                script_asm = vin.get("scriptsig_asm", "")
                witness = vin.get("witness", [])
                
                r, s, pubkey, sighash = decode_der_signature_and_pubkey(script_asm, witness)
                
                if pubkey:
                    valid_signatures += 1
                    print(f"\n  [TXID]: {txid} (Input index {idx})")
                    print(f"    🔓 REVEALED PUBKEY : {pubkey}")
                    print(f"    R : {hex(r)}")
                    print(f"    S : {hex(s)}")
                    print(f"    Z : {hex(z_val)}")
                    print(f"    Sighash Type    : {sighash}")
            
            time.sleep(0.1) # Protect against API rate limiting

        if valid_signatures == 0:
            print("\n  ⚠️ Cryptographic Protection State: ACTIVE")
            print("  This address has no outgoing transactions on record.")
            print("  Its raw Public Key remains hidden behind its SHA256/RIPEMD160 hash state.")

if __name__ == "__main__":
    main()
