import sys
import os
import re
from getpass import getpass
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import Salsa20
import base64

def encrypt_user(user):
    hash_user = SHA256.new(data=bytes(user, encoding = 'UTF-8'))
    hash_user = str(hash_user.hexdigest())
    return hash_user

def encrypt_pass(pass1, hash_user):
    #key derivation
    key = PBKDF2(pass1, hash_user, 32, count=10000, hmac_hash_module=SHA256)
    #Salsa20
    cipher = Salsa20.new(key=key)
    iv = cipher.nonce
    salsa_pass = cipher.encrypt(bytes(pass1, encoding = 'UTF-8'))
    encrypted_password = iv + salsa_pass
    #SHA256
    hash_pass = SHA256.new(data=bytes(str(encrypted_password), encoding = 'UTF-8'))
    hash_pass = str(hash_pass.hexdigest()) + str(base64.b64encode(iv).decode("UTF-8"))
    return hash_pass

def read_file():
    lines = []
    with open('password_base.txt', 'r') as password_base:
        lines = password_base.read().splitlines()
    return lines

def check_if_user_exists(hash_user):
    found = False
    user_list = []
    if os.path.exists('password_base.txt'):
        lines = read_file()
        for line in lines:
            try:
                user, passw = line.strip().split(' ')
                if hash_user == user:
                    found = True
                else:
                    user_list.append(line)
            except:
                print('Base has been tempered with.')
                raise SystemExit()
    return found, user_list

def mark_for_pass_change(hash_user):
    found = False
    user_list = []
    if os.path.exists('password_base.txt'):
        lines = read_file()
        for line in lines:
            try:
                user, passw = line.strip().split(' ')
                flag = passw[-13]
                if hash_user == user:
                    found = True
                    flag = '1'
                user_list.append(user + ' ' + passw[:-13] + flag + passw[-12:])
            except:
                print('Base has been tempered with.')
                raise SystemExit()
    return found, user_list

def check_and_change_pass(hash_user, pass1):
    base_list = []
    found = False
    if os.path.exists('password_base.txt'):
        lines = read_file()
        for line in lines:
            try:
                user, passw = line.strip().split(' ')
                flag = passw[-13]
                passw = passw[:-13] + passw[-12:]
                if hash_user == user:
                    found = True
                    passw = encrypt_pass(pass1, hash_user)
                base_list.append(user + ' ' + passw[:-12] + flag + passw[-12:])
            except:
                print('Base has been tempered with.')
                raise SystemExit()
    return found, base_list

def check_pass_validity(password):
    if len(password) < 8:
        print('Password must contain at least 8 characters.')
        raise SystemExit()
    elif not re.search("[a-z]", password):
        print('Password must contain at least: 1 lower case letter, 1 upper case letter, 1 number and 1 special character.')
        raise SystemExit()
    elif not re.search("[A-Z]", password):
        print('Password must contain at least: 1 lower case letter, 1 upper case letter, 1 number and 1 special character.')
        raise SystemExit()
    elif not re.search("[0-9]", password):
        print('Password must contain at least: 1 lower case letter, 1 upper case letter, 1 number and 1 special character.')
        raise SystemExit()
    elif not re.search("[_@$<>!#%&/()=?*+;:,.-€]" , password):
        print('Password must contain at least: 1 lower case letter, 1 upper case letter, 1 number and 1 special character.')
        raise SystemExit()
    elif re.search("\s" , password):
        print('Password should not contain white space.')
        raise SystemExit()
    return

def add_user(user):
    pass1 = getpass('Password: ')
    check_pass_validity(pass1)
    pass2 = getpass('Repeat Password: ')
    if pass1 != pass2:
        print('User add failed. Password mismatch.')
        raise SystemExit()
    hash_user = encrypt_user(user)
    if check_if_user_exists(hash_user)[0]:
        print('User already exists.')
        raise SystemExit()
    hash_pass = encrypt_pass(pass1, hash_user)
    with open('password_base.txt', 'a+') as password_base:
        password_base.write(hash_user + ' ' + hash_pass[:-12] + '0' + hash_pass[-12:] + '\n')
    print('User ' + user + ' successfuly added.')

def change_pass(user):
    pass1 = getpass('Password: ')
    check_pass_validity(pass1)
    pass2 = getpass('Repeat Password: ')
    if pass1 != pass2:
        print('Password change failed. Password mismatch.')
        raise SystemExit()
    hash_user = encrypt_user(user)
    found, base_list = check_and_change_pass(hash_user, pass1)
    if found:
        with open('password_base.txt', 'w') as password_base:
            for line in base_list:
                password_base.write(line + '\n')
        print('Password change successful.')
        return
    print('User does not exist.')
    raise SystemExit()

def force_pass_change(user):
    hash_user = encrypt_user(user)
    found, user_list = mark_for_pass_change(hash_user)
    if not found:
        print('User does not exist.')
        raise SystemExit()
    with open('password_base.txt', 'w') as password_base:
        for line in user_list:
            password_base.write(line + '\n')
    print('User will be requested to change password on next login.')
    return

def delete_user(user):
    hash_user = encrypt_user(user)
    found, user_list = check_if_user_exists(hash_user)
    if not found:
        print('User does not exist.')
        raise SystemExit()
    with open('password_base.txt', 'w') as password_base:
        for line in user_list:
            password_base.write(line + '\n')
    print('User successfuly removed.')
    return

#main function
function_names = { "add" : add_user, "passwd" : change_pass, "forcepass" : force_pass_change, "del" : delete_user}
if len(sys.argv) == 3:
    function_to_call = sys.argv[1]
    user = sys.argv[2]
    if function_to_call in function_names:
        function_names[function_to_call](user)
else:
    print('Too few or too many arguments.')