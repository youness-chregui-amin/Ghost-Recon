from storage import load_encrypted_json

if __name__ == '__main__':
    import getpass
    import json
    password = getpass.getpass('Enter password to decrypt results: ')
    try:
        data = load_encrypted_json('results.json', password)
        with open('results_decrypted.json', 'w') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print('Decrypted results saved to results_decrypted.json')
    except Exception as e:
        print(f'[!] Failed to decrypt or load results: {e}')
