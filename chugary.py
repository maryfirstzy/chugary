import json
import requests
import time
from urllib.parse import urljoin

INPUT_FILE = "BTC.txt"
OUTPUT_FILE = "raw_transactions.json"
BASE_URL = "https://blockstream.info/api/address/"

def get_transactions_for_address(address):
    # This function guarantees a clean URL by automatically building it safely
    clean_address = address.strip()
    address_endpoint = f"{clean_address}/txs"
    final_url = urljoin(BASE_URL, address_endpoint)
    
    print(f"Connecting to: {final_url}") # Tracks exactly where the script goes
    
    try:
        response = requests.get(final_url)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching data for {clean_address}: {e}")
        return []

def main():
    try:
        with open(INPUT_FILE, 'r') as file:
            addresses = [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print(f"Error: {INPUT_FILE} not found. Please create the file.")
        return

    all_transactions = {}
    print(f"Found {len(addresses)} addresses in {INPUT_FILE}. Fetching data...")

    for address in addresses:
        txs = get_transactions_for_address(address)
        all_transactions[address] = txs
        time.sleep(1) # Prevents getting blocked by the API provider

    with open(OUTPUT_FILE, 'w') as out_file:
        json.dump(all_transactions, out_file, indent=4)

    print(f"\nExtraction complete. Raw transactions saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
