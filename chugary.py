import json
import requests
import time

INPUT_FILE = "BTC.txt"
OUTPUT_FILE = "raw_transactions.json"
API_URL = "https://blockstream.info{}/txs"

def get_transactions_for_address(address):
    url = API_URL.format(address)
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching data for {address}: {e}")
        return []

def main():
    try:
        # Read addresses from BTC.txt
        with open(INPUT_FILE, 'r') as file:
            addresses = [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print(f"Error: {INPUT_FILE} not found. Please create the file.")
        return

    all_transactions = {}

    print(f"Found {len(addresses)} addresses in {INPUT_FILE}. Fetching data...")

    for address in addresses:
        print(f"Extracting transactions for: {address}")
        txs = get_transactions_for_address(address)
        all_transactions[address] = txs
        
        # Add a short delay to avoid hitting API rate limits
        time.sleep(1)

    # Save all extracted raw transactions to a JSON file
    with open(OUTPUT_FILE, 'w') as out_file:
        json.dump(all_transactions, out_file, indent=4)

    print(f"Extraction complete. Raw transactions saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
