from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes

import psycopg2
from psycopg2 import sql
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
from config import config

##################### Encryption #####################

# Generate private and public RSA keys
print("Generating RSA private and public keys....")
RSAkey = RSA.generate(2048)
RSAprivate_key = RSAkey.export_key()
RSApublic_key = RSAkey.publickey().export_key()
print("Done")
print()

# Generate symmetric AES key
print("Generating AES symmetric key....")
AESkey = get_random_bytes(16)
print("Done")
print()

# AES encryption of the data
app_name = input("Enter the app name: ")
password = input("Enter password: ")
AEScipherenc = AES.new(AESkey, AES.MODE_GCM)
print("Encrypting plain text....")
ciphertext, tag = AEScipherenc.encrypt_and_digest(password.encode('utf-8'))
nonce = AEScipherenc.nonce
print("Done")
print()
print(f"Cipher text: {ciphertext}")
print()

# Encryption of AES symmetric key using RSA public key
print("Encrypting AES symmetric key....")
key = RSA.import_key(RSApublic_key)
RSAcipherenc = PKCS1_OAEP.new(key)
enc_session_key = RSAcipherenc.encrypt(AESkey)
print("Done")
print()

##################### File Handling #####################

file_out = open("private_key.pem", "wb")
file_out.write(RSAprivate_key)
file_out.close()

file_out = open("public_key.pem", "wb")
file_out.write(RSApublic_key)
file_out.close()

file_out = open("encrypted_data.bin", "wb")
[ file_out.write(x) for x in (enc_session_key, AEScipherenc.nonce, tag, ciphertext) ]
file_out.close()

params = config()
conn = None

try:
	with psycopg2.connect(**params) as conn:
		conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)

		with conn.cursor() as cur:
			create_test_script = ''' CREATE TABLE IF NOT EXISTS test (
										app_name	VARCHAR(200)	PRIMARY KEY		NOT NULL, 
										password	VARCHAR(200)	NOT NULL
									)'''
			cur.execute(create_test_script)
			insert_test_script = 'INSERT INTO test (app_name, password) VALUES (%s, %s)'
			insert_test_values = (fr"{app_name}", fr"{ciphertext}")
			cur.execute(insert_test_script, insert_test_values)
			print(f"values inserted: {app_name}, {ciphertext}")
			
			create_additional_script = ''' CREATE TABLE IF NOT EXISTS additional (
											app_name			VARCHAR(100)	PRIMARY KEY		NOT NULL,
											enc_session_key		VARCHAR(1000)	NOT NULL,
											nonce 				VARCHAR(1000)	NOT NULL,
											tag					VARCHAR(1000)	NOT NULL
										)'''
			cur.execute(create_additional_script)
			insert_additional_script = 'INSERT INTO additional (app_name, enc_session_key, nonce, tag) VALUES (%s, %s, %s, %s)'
			insert_additional_values = (fr"{app_name}", fr"{enc_session_key}", fr"{nonce}", fr"{tag}")
			cur.execute(insert_additional_script, insert_additional_values)
			print(f"values inserted: {app_name}, {enc_session_key}, {nonce}, {tag}")
			
			# create_test_script = ''' CREATE TABLE IF NOT EXISTS test (
			# 							app_name	VARCHAR(200)	PRIMARY KEY		NOT NULL, 
			# 							password	VARCHAR(200)	NOT NULL,
			# 							enc_session_key		VARCHAR(1000)	NOT NULL,
			# 							nonce 				VARCHAR(1000)	NOT NULL,
			# 							tag					VARCHAR(1000)	NOT NULL
			# 						)'''
			# cur.execute(create_test_script)
			# insert_test_script = 'INSERT INTO test (app_name, password, enc_session_key, nonce, tag) VALUES (%s, %s, %s, %s, %s)'
			# insert_test_values = (fr"{app_name}", fr"{ciphertext}", fr"{enc_session_key}", fr"{nonce}", fr"{tag}")
			# cur.execute(insert_test_script, insert_test_values)
			# print(f"values inserted: {app_name}, {ciphertext}, {enc_session_key}, {nonce}, {tag}")

except Exception as error:
	print(f"Error: {error}")

finally:
	if conn is not None:
		conn.close()
