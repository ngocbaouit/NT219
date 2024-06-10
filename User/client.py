import os, json, requests
from flask import Flask, request, jsonify, render_template
import KEM
from flask_mysqldb import MySQL
import hashlib
import time

client = Flask(__name__)

def load_mysql_config(filename="./db_config.json"):
    with open(filename) as config_file:
        config = json.load(config_file)
    return config

#Load config database
mysql_config=load_mysql_config()

print(mysql_config["host"])
# config
client.config["MYSQL_HOST"] = mysql_config["host"]
client.config["MYSQL_USER"] = mysql_config["user"]
client.config["MYSQL_PASSWORD"] = mysql_config["password"]
client.config["MYSQL_DB"] = "client"

# Initialize Data
mysql = MySQL(client)

@client.route("/signup", methods=["POST"])
def signup():
    #auth
    auth = request.authorization
    if not auth:
        return 'Missing something!', 401 

    # create key pair
    publicKey, privateKey = KEM.k_pke_keygen()

    publicKey_pem = KEM.dktoPEM(publicKey)
    privateKey_pem = KEM.dktoPEM(privateKey)
    
    # create encap, decap key of local
    ek, dk = KEM.kem_key_convert(publicKey, privateKey)

    payload= json.dumps({
        "ek": publicKey_pem
    })

    headers = {
        "Content-Type": "application/json"
    }

    response = requests.post(
        f"http://127.0.0.1:8000/session", data=payload, headers=headers
    )

    public_server_key= None
    cipher = None
    session_id= None
    if response.status_code==201:
        temp = json.loads(response.text)
        public_server_key = temp["ek"]
        cipher = bytes.fromhex(temp["c"]) #convert from hex to bytes
        session_id = temp["id"]
    else:
        return "Failed", 500

    # get shared_key from cipher
    shared_key= KEM.ml_kem_decaps(cipher, dk)
    cur = mysql.connection.cursor()
    result = cur.execute(
        "insert into key_management (session_id, private_key, shared_key, public_server_key) values (%s, %s, %s, %s)",
        (session_id, privateKey_pem, shared_key.hex(), public_server_key,)
        )

    if result < 0:
        return "Cannot save to local", 500

    print("Done keygen")
    #sign up
    username=auth.username
    password=auth.password
    encrypted_password = KEM.k_pke_encrypt(shared_key, auth.password.encode('utf-8'))
    print(auth.username)
    print(auth.password)
    print(f"Shared Key: {shared_key.hex()}")
    print(encrypted_password.hex())
    data = {
        "id" : session_id,
        "username" : username,
        "password" : encrypted_password.hex()
    }

    response= requests.post(
        f"http://127.0.0.1:8000/signup", data=json.dumps(data), headers=headers
    )

    if response.status_code==201:
        cur.connection.commit()
        cur.close()
        return "Sign up successfully!", 201
    # Xoa session at local
    res=cur.execute(f"delete from key_management where session_id=%s", (session_id, ))
    cur.connection.commit()
    cur.close()
    return "Failed to sign up!"

@client.route("/login", methods=["POST"])
def login():
    #auth
    auth = request.authorization
    if not auth:
        return 'Missing something!', 401 

    # create key pair
    publicKey, privateKey = KEM.k_pke_keygen()

    publicKey_pem = KEM.dktoPEM(publicKey)
    privateKey_pem = KEM.dktoPEM(privateKey)
    
    # create encap, decap key of local
    ek, dk = KEM.kem_key_convert(publicKey, privateKey)

    payload= json.dumps({
        "ek": publicKey_pem
    })

    headers = {
        "Content-Type": "application/json"
    }

    response = requests.post(
        f"http://127.0.0.1:8000/session", data=payload, headers=headers
    )

    public_server_key= None
    cipher = None
    session_id= None
    if response.status_code==201:
        temp = json.loads(response.text)
        public_server_key = temp["ek"]
        cipher = bytes.fromhex(temp["c"]) #convert from hex to bytes
        session_id = temp["id"]
    else:
        return "Failed", 500

    # get shared_key from cipher
    shared_key= KEM.ml_kem_decaps(cipher, dk)
    cur = mysql.connection.cursor()
    result = cur.execute(
        "insert into key_management (session_id, private_key, shared_key, public_server_key) values (%s, %s, %s, %s)",
        (session_id, privateKey_pem, shared_key.hex(), public_server_key,)
        )

    if result < 0:
        return "Cannot save to local", 500

    print("Done keygen")
    #sign up
    username=auth.username
    password=auth.password
    encrypted_password = KEM.k_pke_encrypt(shared_key, auth.password.encode('utf-8'))
    print(auth.username)
    print(auth.password)
    print(f"Shared Key: {shared_key.hex()}")
    print(encrypted_password.hex())
    data = {
        "id" : session_id,
        "username" : username,
        "password" : encrypted_password.hex()
    }

    response= requests.post(
        f"http://127.0.0.1:8000/login", data=json.dumps(data), headers=headers
    )

    if response.status_code==201:
        cur.connection.commit()
        cur.close()
        return "Login successfully!", 201
    elif response.status_code == 301:
        res=cur.execute(f"delete from key_management where session_id=%s", (session_id, ))
        cur.connection.commit()
        cur.close()
        return "Already login!", 301
    
    # Xoa session at local
    res=cur.execute(f"delete from key_management where session_id=%s", (session_id, ))
    cur.connection.commit()
    cur.close()
    return "Failed to login!"

@client.route("/logout", methods=["POST"])
def logout():
    cur = mysql.connection.cursor()
    res= cur.execute(
        f"select * from key_management ",
    )

    isLogOut = 0
    rows = cur.fetchall()
    for row in rows:
    # Xử lý từng hàng dữ liệu
        # data={
        #     "session_id": row[1]
        # }
        # headers = {
        # "Content-Type": "application/json"
        # }
        response = requests.post(
            f"http://127.0.0.1:8000/logout/{row[1]}"
        )
        if response.status_code==200:
            isLogOut +=1
    if res > 0:
        res_del=cur.execute(
            f"delete from key_management",
        )
        mysql.connection.commit()

    if isLogOut == len(rows):
        mysql.connection.commit()
        cur.close()
        return "All current is logged Out!", 201
    mysql.connection.commit()
    cur.close()
    return "Some Failed to logged out!", 500
if __name__ == "__main__":
    client.run(host="0.0.0.0", port=50000, debug=True)