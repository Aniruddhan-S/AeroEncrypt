from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP

import psycopg2
import psycopg2.extras
from psycopg2 import sql
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
from config import config

app = input("Enter the app name to retrieve the password: ")

##################### File Handling #####################

key = RSA.import_key(open("private_key.pem").read())

file_in = open("encrypted_data.bin", "rb")
enc_session_key, AESnonce, tag, ctext = \
    [ file_in.read(x) for x in (key.size_in_bytes(), 16, 16, -1) ]

params = config()
conn = None

try:
	with psycopg2.connect(**params) as conn:
		conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)

		with conn.cursor() as cur:

			cur.execute('SELECT * FROM test WHERE app_name=%s', (app,))
			record = cur.fetchone()
			
			ciphertext = record[1]
			CipherText = bytes(ciphertext, 'utf-8')
			
			enc_sess_key = record[2]
			Enc_Sess_Key = bytes(enc_sess_key, 'utf-8')
			
			nonce = record[3]
			Nonce = bytes(nonce, 'utf-8')
			
			Tag = record[4]
			TAG = bytes(Tag, 'utf-8')

			# print()
			# print(type(enc_sess_key))
			# print(type(enc_session_key))

			# cur.execute('SELECT * FROM additional WHERE app_name=%s', (app,))
			# addi_record = cur.fetchone()
			# enc_sess_key = addi_record[1]
			# nonce = addi_record[2]
			# Tag = addi_record[3]
			

except Exception as error:
	print(f"Error: {error}")

finally:
	if conn is not None:
		conn.close()

print()
print(type(CipherText))
print(type(Enc_Sess_Key))
print(type(Nonce))
print(type(TAG))
print()

# if(enc_session_key == enc_sess_key):
# 	print("yes")
# print()
# print(enc_session_key)
# print()
# print(enc_sess_key)
# print()
##################### Decryption #####################

# Decryption of AES symmetric key using RSA private key
print("Decrypting AES symmetric key....")
RSAcipherdec = PKCS1_OAEP.new(key)
dec_session_key = RSAcipherdec.decrypt(Enc_Sess_Key)
print("Done")
print()

# AES decryption of data
print("Decrypting data....")
AEScipherdec = AES.new(dec_session_key, AES.MODE_GCM, Nonce)
data = AEScipherdec.decrypt_and_verify(CipherText, TAG)
print("Done")
print()
print("Decrypted data:")
print(data.decode("utf-8"))