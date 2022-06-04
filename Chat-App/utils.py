import hashlib
from Crypto.PublicKey import RSA 
import hmac
import string
import random


user_rsa_key_registry = {}

def generate_rsa_key(key_size=2048):
    return RSA.generate(key_size)

def get_private_and_public_rsa_keys(key_size=2048):
    key = generate_rsa_key(key_size)
    return key, key.public_key()

def generate_public_and_private_rsa_keys_for_user(username):
    private_key, public_key = get_private_and_public_rsa_keys()
    user_rsa_key_registry[username] = private_key
    return private_key, public_key

def generate_random_string(length):
    return ''.join(random.choice(string.ascii_letters + string.digits + string.punctuation) for i in range(length))

def generate_master_key():
    return generate_random_string(48)

def derive_keys(master_key):
    random_index_point_tuple = [random.randint(0, len(master_key) - 33) for i in range(6)]
    print(random_index_point_tuple)
    return {
        'client_write_key': master_key[random_index_point_tuple[0]:random_index_point_tuple[0] + 32],
        'server_write_key': master_key[random_index_point_tuple[1]:random_index_point_tuple[1] + 32],
        'client_MAC_key': master_key[random_index_point_tuple[2]:random_index_point_tuple[2] + 32],
        'server_MAC_key': master_key[random_index_point_tuple[3]:random_index_point_tuple[3] + 32],
        'client_IV_key': master_key[random_index_point_tuple[4]:random_index_point_tuple[4] + 32],
        'server_IV_key': master_key[random_index_point_tuple[5]:random_index_point_tuple[5] + 32]
    }

def convert_string_to_bytes(string):
    return string.encode('utf-8')

secret_hmac_key = generate_master_key()

def get_hashed_message(message, master_key=secret_hmac_key):
    return hmac.new(convert_string_to_bytes(secret_hmac_key), convert_string_to_bytes(message), digestmod=hashlib.sha256).hexdigest()

def find_if_actual_message_match_with_hashed_one(message, hashed_message):
    return hashed_message == get_hashed_message(message)

derived_key_map = derive_keys(secret_hmac_key)

print(find_if_actual_message_match_with_hashed_one('Hello', get_hashed_message('Hello')))
print(derived_key_map)

generate_public_and_private_rsa_keys_for_user('user1')
generate_public_and_private_rsa_keys_for_user('user2')
generate_public_and_private_rsa_keys_for_user('user3')

print(user_rsa_key_registry.keys())