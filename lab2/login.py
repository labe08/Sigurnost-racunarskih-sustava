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

def encrypt_pass_check(pass1, hash_user, iv):
    iv = base64.b64decode(iv)
    #key derivation
    key = PBKDF2(pass1, hash_user, 32, count=10000, hmac_hash_module=SHA256)
    #Salsa20
    cipher = Salsa20.new(key=key, nonce = iv)
    salsa_pass = cipher.encrypt(bytes(pass1, encoding = 'UTF-8'))
    encrypted_password = iv + salsa_pass
    #SHA256
    hash_pass = SHA256.new(data=bytes(str(encrypted_password), encoding = 'UTF-8'))
    hash_pass = str(hash_pass.hexdigest()) + str(base64.b64encode(iv).decode("UTF-8"))
    return hash_pass

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

def force_pass_change(hash_user):
    pass1 = getpass('New password: ')
    check_pass_validity(pass1)
    pass2 = getpass('Repeat new password: ')
    if pass1 != pass2:
        print('User add failed. Password mismatch.')
        raise SystemExit()
    passw = encrypt_pass(pass1, hash_user)
    return passw

def read_file():
    lines = []
    with open('password_base.txt', 'r') as password_base:
        lines = password_base.read().splitlines()
    return lines

def check_username_password_and_flag(hash_user, passwd):
    correct = False
    user_list = []
    if os.path.exists('password_base.txt'):
        lines = read_file()
        for line in lines:
            try:
                user, passw = line.strip().split(' ')
                flag = passw[-13]
                passw = passw[:-13] + passw[-12:]
                if hash_user == user:
                    pass_to_check = encrypt_pass_check(passwd, hash_user, passw[-12:])
                    if pass_to_check == passw:
                        correct = True
                        if flag == '1':
                            passw = force_pass_change(hash_user)
                            flag = '0'
                user_list.append(user + ' ' + passw[:-12] + flag + passw[-12:])
            except:
                print('Base has been tempered with.')
                raise SystemExit()
    if correct:
        with open('password_base.txt', 'w') as password_base:
            for line in user_list:
                password_base.write(line + '\n')
    return correct

def autenticate_user(username, password):
    hash_user = encrypt_user(username)
    if check_username_password_and_flag(hash_user, password):
        return True
    return False

#main function
if len(sys.argv) == 2:
    username = sys.argv[1]
    password = getpass('Password: ')
    if autenticate_user(username, password):
        print('Login successful.')
    else: print('Username or password incorrect.')
else:
    print('Too few or too many arguments.')