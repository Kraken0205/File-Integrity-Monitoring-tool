import os
import sqlite3
import hashlib
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import requests
import json

print('''
 ______ _____ _      ______    __  __  ____  _   _ _____ _______ ____  _____  _____ _   _  _____     _______     ________ _______ ______ __   __
 |  ____|_   _| |    |  ____|  |  \/  |/ __ \| \ | |_   _|__   __/ __ \|  __ \|_   _| \ | |/ ____|   / ____\ \   / / ____|__   __|  ____|  \/  |
 | |__    | | | |    | |__     | \  / | |  | |  \| | | |    | | | |  | | |__) | | | |  \| | |  __   | (___  \ \_/ / (___    | |  | |__  | \  / |
 |  __|   | | | |    |  __|    | |\/| | |  | | . ` | | |    | | | |  | |  _  /  | | | . ` | | |_ |   \___ \  \   / \___ \   | |  |  __| | |\/| |
 | |     _| |_| |____| |____   | |  | | |__| | |\  |_| |_   | | | |__| | | \ \ _| |_| |\  | |__| |   ____) |  | |  ____) |  | |  | |____| |  | |
 |_|    |_____|______|______|  |_|  |_|\____/|_| \_|_____|  |_|  \____/|_|  \_\_____|_| \_|\_____|  | ____/   |_| |_____/   |_|  |______|_|  |_|

FMS | Developed by: Nimesh Shrestha''')
db_file = 'file_hashes.db'
discord_webhook_url = 'https://discord.com/api/webhooks/1205869970098094091/7dR_l-y58ZJDLD65Ka8lcS_dM17cK9n98JtAk6ye1xDHbFTzL9NT5OqkQDYTU176PJUL'

def calculate_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def send_to_discord(message):
    payload = {'content': message}
    try:
        response = requests.post(discord_webhook_url, json=payload)
        if response.status_code != 200:
            print(f"Failed to send message to Discord. Status code: {response.status_code}")
    except Exception as e:
        print(f"An error occurred while sending message to Discord: {e}")

class MyHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.is_directory:
            return
        file_path = event.src_path
        if file_path.endswith('.db-journal'):
            return
        file_name = os.path.basename(file_path)
        file_hash = calculate_file_hash(file_path)

        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()

        cursor.execute('SELECT hash FROM file_hashes WHERE file_name = ?', (file_name,))
        row = cursor.fetchone()

        if row is None:
            cursor.execute('INSERT INTO file_hashes (file_name, hash) VALUES (?, ?)', (file_name, file_hash))
            send_to_discord(f'New file detected: {file_name} with hash {file_hash}')
        else:
            old_hash = row[0]
            if old_hash != file_hash:
                cursor.execute('UPDATE file_hashes SET hash = ? WHERE file_name = ?', (file_hash, file_name))
                send_to_discord(f'File modified: {file_name}. Old hash: {old_hash}, New hash: {file_hash}')
                print(f'File modified: {file_name}. Old hash: {old_hash}, New hash: {file_hash}')

        conn.commit()
        conn.close()

conn = sqlite3.connect(db_file)
cursor = conn.cursor()
cursor.execute('CREATE TABLE IF NOT EXISTS file_hashes (file_name TEXT, hash TEXT)')
conn.commit()

for file_name in os.listdir('.'):
    if os.path.isfile(file_name):
        file_hash = calculate_file_hash(file_name)
        cursor.execute('INSERT OR IGNORE INTO file_hashes (file_name, hash) VALUES (?, ?)', (file_name, file_hash))
conn.commit()
conn.close()

event_handler = MyHandler()
observer = Observer()
observer.schedule(event_handler, path='.', recursive=False)
observer.start()

print("Listening for changes in files...")

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    observer.stop()

observer.join()
