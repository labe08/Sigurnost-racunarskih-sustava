import os
import sys
from Crypto.Hash import HMAC
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad
from Crypto.Cipher import Salsa20
import base64

#inicijalizacija baze i master lozinke
def initBase(master_pass):
    if len(master_pass) != 1:
        print('Master password incorrect or integrity check failed.')
        raise SystemExit()
    hash_master = SHA256.new(data=bytes(master_pass[0], encoding = 'UTF-8'))
    file_name = str(hash_master.hexdigest()) + '.txt'
    if os.path.exists(file_name):
        print('Master password incorrect or integrity check failed.')
        raise SystemExit()
    password_base = open(file_name, 'a+')
    password_base.close()
    print('Password manager initialized.')

#pohrana para: adresa, lozinka
def storePair(argum):
    if len(argum) != 3:
        print('Master password incorrect or integrity check failed.')
        raise SystemExit()
    master_pass, address, password = argum
    hash_master = SHA256.new(data=bytes(master_pass, encoding = 'UTF-8'))
    file_name = str(hash_master.hexdigest()) + ".txt"
    if not os.path.exists(file_name):
        print('Master password incorrect or integrity check failed.')
        raise SystemExit()
    password_base = open(file_name, 'r')
    hash_address = SHA256.new(data=bytes(address, encoding = 'UTF-8'))
    hash_address = str(hash_address.hexdigest())
    read_file = password_base.read().splitlines()
    password_base.close()

    #key derivation
    key = PBKDF2(master_pass, hash_address, 32, count=10000, hmac_hash_module=SHA256)
    key1 = key[:16]
    key2 = key[16:]

    #Salsa20
    cipher = Salsa20.new(key=key1)
    iv = cipher.nonce
    encrypted_message = cipher.encrypt(bytes(password, encoding = 'UTF-8'))
    encrypted_password = iv + encrypted_message

    #HMAC
    h = HMAC.new(key2, digestmod=SHA256)
    h.update(encrypted_message)
    digested = h.hexdigest()
    
    end_string = encrypted_password + bytes(digested, encoding = "UTF-8")

    #pretraživanje postoji li već lozinka za zadanu adresu
    found = False
    if len(read_file) != 0:
        for count in range(len(read_file)):
            add, passw = read_file[count].split(', ')
            if hash_address == add:
                read_file[count] = add + ', ' + str(base64.b64encode(end_string).decode("UTF-8"))
                found = True
                break
    if not found:
        read_file.append(hash_address + ', ' + str(base64.b64encode(end_string).decode("UTF-8")))

    password_base = open(file_name, 'w')
    for line in read_file:
        password_base.write(line + '\n')
    password_base.close()
    print('Stored password for ' + address)

#dohvaćanje lozinke za zadanu adresu
def getPassword(argum):
    if len(argum) != 2:
        print('Master password incorrect or integrity check failed.')
        raise SystemExit()
    master_pass, address = argum
    hash_master = SHA256.new(data=bytes(master_pass, encoding = 'UTF-8'))
    file_name = str(hash_master.hexdigest()) + ".txt"
    if not os.path.exists(file_name):
        print('Master password incorrect or integrity check failed.')
        raise SystemExit()
    hash_address = SHA256.new(data=bytes(address, encoding = 'UTF-8'))
    hash_address = str(hash_address.hexdigest())
    password_base = open(file_name, 'r')
    for line in password_base.readlines():
        add, passw = line.strip().split(', ')
        if add == hash_address:

            try:
                #key derivation
                key = PBKDF2(master_pass, hash_address, 32, count=10000, hmac_hash_module=SHA256)
                key1 = key[:16]
                key2 = key[16:]

                #Salsa20
                passw = base64.b64decode(passw)
                mac = passw[-64:]
                passw = passw[:-64]
                iv = passw[:8]
                encrypted_message = passw[8:]
                cipher = Salsa20.new(key=key1, nonce = iv)
                decrypted_message = cipher.decrypt(encrypted_message)

                #HMAC
                h = HMAC.new(key2, digestmod=SHA256)
                h.update(encrypted_message)
                h.hexverify(mac)
                print('Password for ' + address + ' is: ' + decrypted_message.decode("UTF-8"))

            except ValueError:
                print('Master password incorrect or integrity check failed.')

            return

    print('Master password incorrect or integrity check failed.')

#main function
function_names = { "init" : initBase, "put" : storePair, "get" : getPassword}
if len(sys.argv) > 2:
    function_to_call = sys.argv[1]
    arguments = sys.argv[2:]
    if function_to_call in function_names:
        function_names[function_to_call](arguments)
