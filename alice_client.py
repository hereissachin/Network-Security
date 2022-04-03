#this is ALICE as a client

def xored(hex1, hex2):
    # print(hex1)
    # print(hex2)
    p1 = int.from_bytes(bytes.fromhex(hex1),"big")
    p2 = int.from_bytes(bytes.fromhex(hex2),"big")
    r = p1^p2
    return (r).to_bytes(length=len('{}'.format(r)),byteorder='big').hex()[-16:]

#generating four keys
def four_keys(mk):
    k = int.from_bytes(bytes.fromhex(mk),"big")

    s = "{}".format(k)


    keys = []
    f = s[:2]
    mid = s[2:-2]
    l = s[-2:]

    for i in range(0,4):
        mid = mid[-1] + mid[:-1]
        temp = int(f+mid+l)
        keys.append((temp).to_bytes(length=len('{}'.format(temp)),byteorder='big').hex()[-16:])
    return keys



def enc(plaintext,key):
    # print(plaintext)
    plaintext = bytes.fromhex(plaintext)
    if len(plaintext)%8 != 0:
        padding = " ".encode()
        for x in range(0,8 - len(plaintext)%8):
            plaintext += padding
    
    ebc_cipher = DES3.new(key, DES3.MODE_ECB)
    ebc = ebc_cipher.encrypt(plaintext)
    # ebc_d_cipher = DES3.new(keyBobAlice, DES3.MODE_ECB)
    return ebc.hex()


def dec(msg,key):
    
    msg = bytes.fromhex(msg)

    if len(msg)%8 != 0:
        padding = " ".encode()
        for x in range(0,8 - len(msg)%8):
            msg += padding

    d_cipher = DES3.new(key, DES3.MODE_ECB)

    plaintext = d_cipher.decrypt(msg)
    
    return plaintext.hex()

def enc_msg(plaintext,key):
#     plaintext = bytes.fromhex(plaintext)
    if len(plaintext)%8 != 0:
        padding = " ".encode()
        for x in range(0,8 - len(plaintext)%8):
            plaintext += padding
    
    ebc_cipher = DES3.new(key, DES3.MODE_ECB)
    ebc = ebc_cipher.encrypt(plaintext)
    # ebc_d_cipher = DES3.new(keyBobAlice, DES3.MODE_ECB)
    return ebc.hex()




def hash(msg):
    #msg should be string
    return hashlib.sha1(msg.encode()).hexdigest()
  
def get_len(li):
    li = "".join(li)
    l = "{0:b}".format(len(li))
    if len(l)%8 != 0:
        l = '0'*(8 - len(l)) + l
    return l

def get_ind(b_str):
    return int(b_str, 2)
    


import socket
import pickle
from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
import hashlib



#data for performing DH key exchange

key = b'\xfdd\x7fm\x07v@/h\rT\x04\xf2\xc1%8\xd3\xe6\xc4\xba\xefbI\x97'

g = 1907
p = 784313

sb = 12077


ALICE_socket_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM);

 
ALICE_ip = "127.0.0.1"

ALICE_port = 2345


ALICE_socket_client.connect((ALICE_ip,ALICE_port));
 
#this records all the transaction happening

data = ""

r_alice = get_random_bytes(8).hex()



# starting the exchange

print("\nALICE : Starting Handshake\n")

# print(get_len(["DES3"] + [enc(r_alice,key)]))


# making message one 
m_1 = ["0"]+["01"]+[get_len(["DES3"] + [enc(r_alice,key)])] + ["DES3"] + [enc(r_alice,key)]
# print("".join(m_1))

ALICE_socket_client.send(pickle.dumps("".join(m_1)));

data = data + "".join(m_1)

# print("".join(m_1)[11:11+get_ind(get_len(["DES3"] + [r_alice]))])
# print("".join(m_1)[11:])



#print("Sending my T_b")




# 
print("-----------------------------------")
print("R_alice : {}".format(r_alice))
print("Encrypt : {}".format(enc(r_alice,key)))
print("Message Sent to BOB : " + "".join(m_1))
# print("Number Sent to BOB : " + str(r_alice))
print("-----------------------------------")



#print("\n-----------------------------------")


m_2 = pickle.loads(ALICE_socket_client.recv(1024))

# if m_2[]

data = data + m_2

print("M2 Received")

print("Cipher choosed : " + str(m_2[11:15]))

r_bob = m_2[11:11+get_ind(m_2[3:11])][4:]
certi = m_2[11+get_ind(m_2[3:11]):]

print("R_bob : {}".format(r_bob))
r_bob = dec(r_bob,key)
print("Decry : {}".format(r_bob))

# print(r_bob)
print(certi)

print("-----------------------------------")

print("Generating Master Key")

mk = xored(r_bob, r_alice)

print("Master Key : {}".format(mk))


print("-----------------------------------")


print("Alice : Sending hash to BOB")
print(data)

server_hash = hash(data+"SERVER")

client_hash = hash(data + "CLIENT")

#Reciving hash from BOB



ALICE_socket_client.send(pickle.dumps(client_hash));
print("-----------------------------------")

print("Alice : Receiving Hash From BOB")
bob_hash = pickle.loads(ALICE_socket_client.recv(1024))

if bob_hash == server_hash:
    print("BOB hash Authenticated")
else:
    print("BOB hash NOT Authenticated")
    print(bob_hash)
    print(server_hash)
# print("M3 sent----------------------------------")

#generating four keys
print("-----------------------------------")
print("Generating Four Keys")
keys = four_keys(mk)
print("Alice Encry Key : {}".format(keys[0]))
print("Alice Auth. Key : {}".format(keys[1]))
print("Bob  Encry  Key : {}".format(keys[2]))
print("Bob  Auth.  Key : {}".format(keys[3]))



print("-----------------------------------")

print("Data Transfer phase")
b_h = pickle.loads(ALICE_socket_client.recv(1024))

r = ''
q = 0 

try:
    for i in range(0,int(133136/8)):
        r_data = pickle.loads(ALICE_socket_client.recv(1024))
        # print(r_data)
        if r_data == "DONE-DONE-Transfer":
            break

        q = q + len(r_data)
        # print(q)
        r = r + r_data 


    print("File Transfered")
    print("Encrypted 16 bytes : \n{}".format(r[:32]))

    # print("Decrypted 16 bytes : ")


    # print(bytes.fromhex(dec(r[:16],keys[0])).decode())

    # print(r[:10])
    # print(len(r))
    content = bytes.fromhex(dec(r,keys[0])).decode()

    # print(content)

except:
    pass

bob_hh = pickle.loads(ALICE_socket_client.recv(1024))

if enc(b_h,keys[1]) == enc(bob_hh,keys[1]):
    print("Integrity protected : Hash Matched")
else:
    print("Integrity Not Protected Hash Dont Matched")


print("Exchange Complete Closing Connection")


 