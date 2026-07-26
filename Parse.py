import json

INPUT_JSON = "raw_transactions.json"

def parse_data():
    try:
        with open(INPUT_JSON, 'r') as file:
            data = json.load(file)
    except FileNotFoundError:
        print(f"Error: {INPUT_JSON} not found. Please run your chugary.py script first.")
        return
    except json.JSONDecodeError:
        print(f"Error: {INPUT_JSON} seems to contain broken or incomplete JSON data.")
        return

    # Loop through each target address tracked in the JSON file
    for target_address, tx_list in data.items():
        print(f"\n==================================================")
        print(f"SUMMARY FOR ADDRESS: {target_address}")
        print(f"Total Transactions Found: {len(tx_list)}")
        print(f"==================================================")

        for index, tx in enumerate(tx_list, 1):
            txid = tx.get("txid", "Unknown TXID")
            status = tx.get("status", {})
            confirmed = status.get("confirmed", False)
            block_time = status.get("block_time", None)
            
            print(f"\n[Tx #{index}] ID: {txid}")
            print(f"  Confirmed: {confirmed}")
            if block_time:
                import datetime
                date_str = datetime.datetime.fromtimestamp(block_time).strftime('%Y-%m-%d %H:%M:%S')
                print(f"  Date/Time: {date_str}")
            
            # Print Outputs (Where the money went)
            print("  Outputs:")
            for output in tx.get("vout", []):
                address = output.get("scriptpubkey_address", "Unknown Address / Change")
                satoshis = output.get("value", 0)
                btc_value = satoshis / 100000000 # Converts Satoshis back to BTC
                print(f"    -> {address}: {btc_value:.8f} BTC ({satoshis} sats)")

if __name__ == "__main__":
    parse_data()
