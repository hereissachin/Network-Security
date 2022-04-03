# This is bob as a server

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

#data needed for exchange

key = b'\xfdd\x7fm\x07v@/h\rT\x04\xf2\xc1%8\xd3\xe6\xc4\xba\xefbI\x97'


g = 1907
p = 784313
sa = 160031

print("\nListening for someone to Start ") 

BOB_socket_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM);

 
BOB_ip = "127.0.0.1"

BOB_port = 2345

BOB_socket_server.bind((BOB_ip,BOB_port));

BOB_socket_server.listen();

#record keeping of all the message exchange



while(True):

    (alice_socket_client, alice_meta) = BOB_socket_server.accept();

    data = ""
    #Staring the process and sending message to alice



    print("\nBOB : I am BOB, Received Message form Alice {} : {}\n".format(alice_meta[0], alice_meta[1]))


    #print(alice_meta)

    #response form alice

    m_1 = pickle.loads(alice_socket_client.recv(1024))
    data = data + m_1
    print(m_1[11:11+get_ind(m_1[3:11])])

    if m_1[0] == "0":
        print("Content Type is Handshake")

    if m_1[1:3] == "01":
        print("Version Matched to 01")
    else:
        print("Version Not Matched")
        break

    m_1 = m_1[11:11+get_ind(m_1[3:11])]

    print("Cipher choosed : " + str(m_1[:4]))
    r_alice = m_1[4:]
    
    print("-----------------------------------")
    print("R_alice from alice Encry : " + str(r_alice))
    print("R_alice from alice Decry : " + str(dec(r_alice,key)))
    # print("\n-----------------------------------")
    r_alice = dec(r_alice,key)

    

    r_bob = get_random_bytes(8).hex()
    
    m_2 = ["0"]+["01"]+[get_len(["DES3"] + [enc(r_bob,key)])] + ["DES3"] + [enc(r_bob,key)] + ["CERTI"]

    m_2 = "".join(m_2)


    alice_socket_client.send(pickle.dumps(m_2));
    data = data + m_2

    print("-----------------------------------")
    print("R_Bob : {}".format(r_bob))
    print("Encrypt : {}".format(enc(r_bob,key)))
    # r_bob = enc(r_bob,key)
    print("Message Sent to alice : " + str(m_2))
    print("-----------------------------------")


    print("Generating Master Key")

    mk = xored(r_bob, r_alice)

    print("Master Key : {}".format(mk))
    print("-----------------------------------")

    print("BOB : Receiving Hash From Alice")
    print(data)


    server_hash = hash(data+"SERVER")

    client_hash = hash(data +"CLIENT")

    bob_hash = pickle.loads(alice_socket_client.recv(1024))
    
    if bob_hash == client_hash :
        print("Alice Hash Authenticated")

    else:
        print("Alice Hash Not Authenticated")

    print("-----------------------------------")

    print("BOB : Sending Hash To Alice")
    alice_socket_client.send(pickle.dumps(server_hash));

    print("-----------------------------------")
    print("Generating Four Keys")
    keys = four_keys(mk)
    print("Alice Encry Key : {}".format(keys[0]))
    print("Alice Auth. Key : {}".format(keys[1]))
    print("Bob  Encry  Key : {}".format(keys[2]))
    print("Bob  Auth.  Key : {}".format(keys[3]))
    

    print("-----------------------------------\n")


    fo = open("file.txt",'r')
    line = fo.read()
    fo.close()

    lines = line.encode()

    sending_data = enc_msg(lines,keys[0])


    print(len(sending_data))

    alice_socket_client.send(pickle.dumps(hash(sending_data)))


    c = 0
    for i in range(0,int(133136/8)):
        # print(c, c+8)
        alice_socket_client.send(pickle.dumps(sending_data[c:c+8]));
        c += 8


    alice_socket_client.send(pickle.dumps("DONE-DONE-Transfer"));

    print("Transfered File")


    alice_socket_client.send(pickle.dumps(hash(sending_data)))

    # print(bytes.fromhex(dec(sending_data[:16],keys[0])).decode())

    print("Exchange Complete Closing Connection")
    
    # alice_socket_client.close()

    # break
