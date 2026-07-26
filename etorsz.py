import json
import hashlib

INPUT_JSON = "raw_transactions.json"

def decode_der_signature(sig_hex):
    """
    Parses a hexadecimal DER-encoded ECDSA signature to extract R and S.
    """
    try:
        sig_bytes = bytes.fromhex(sig_hex)
        # Check DER header byte (0x30)
        if sig_bytes[0] != 0x30:
            return None, None
        
        # Length of the remaining signature data
        # sig_bytes[1] is total length
        
        # Extract R
        if sig_bytes[2] != 0x02:
            return None, None
        r_length = sig_bytes[3]
        r_start = 4
        r_end = r_start + r_length
        r_bytes = sig_bytes[r_start:r_end]
        
        # Extract S
        if sig_bytes[end_r := r_end] != 0x02:
            return None, None
        s_length = sig_bytes[end_r + 1]
        s_start = end_r + 2
        s_end = s_start + s_length
        s_bytes = sig_bytes[s_start:s_end]
        
        # Strip leading zero bytes added by DER encoding for sign preservation
        if r_bytes[0] == 0x00: r_bytes = r_bytes[1:]
        if s_bytes[0] == 0x00: s_bytes = s_bytes[1:]
        
        return r_bytes.hex(), s_bytes.hex()
    except Exception:
        return None, None

def extract_crypto_data():
    try:
        with open(INPUT_JSON, 'r') as file:
            data = json.load(file)
    except Exception as e:
        print(f"Error reading JSON file: {e}")
        return

    for address, tx_list in data.items():
        print(f"\n==================================================")
        print(f"EXTRACTING CRYPTO PARAMS FOR ADDRESS: {address}")
        print(f"==================================================")

        for tx in tx_list:
            txid = tx.get("txid")
            print(f"\nTransaction ID: {txid}")
            
            # Loop through all inputs (vin) to find signatures
            for idx, vin in enumerate(tx.get("vin", [])):
                print(f"  Input Index [{idx}]:")
                
                # Case 1: Legacy / P2SH addresses store signature in scriptsig_asm
                script_asm = vin.get("scriptsig_asm", "")
                # Case 2: SegWit addresses store signature in the witness array
                witness = vin.get("witness", [])
                
                sig_hex = None
                
                # Check script_asm for signature tokens (usually starts with OP_PUSHBYTES)
                if "OP_PUSHBYTES" in script_asm:
                    parts = script_asm.split()
                    for part in parts:
                        # Signatures are typically between 70-73 bytes (140-146 hex chars)
                        if len(part) >= 140 and len(part) <= 146:
                            sig_hex = part
                            break
                            
                # Check witness array if legacy script was empty
                if not sig_hex and witness:
                    for item in witness:
                        if len(item) >= 140 and len(item) <= 146:
                            sig_hex = item
                            break
                
                if sig_hex:
                    # Bitcoin signatures usually end with a 1-byte Sighash flag (e.g., '01' for SIGHASH_ALL)
                    # We strip the sighash flag to parse the pure DER signature
                    der_sig = sig_hex[:-2]
                    sighash_flag = sig_hex[-2:]
                    
                    r, s = decode_der_signature(der_sig)
                    
                    if r and s:
                        print(f"    Sighash Flag: {sighash_flag}")
                        print(f"    R: {r}")
                        print(f"    S: {s}")
                        print(f"    [Note on Z]: Z requires serialization of the specific transaction spending path.")
                    else:
                        print("    Could not parse DER signature structure.")
                else:
                    print("    No ECDSA signature found in this input (it may be an unspent output or a different script type).")

if __name__ == "__main__":
    extract_crypto_data()
