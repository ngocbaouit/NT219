import os, json, time
from flask import Flask, request, jsonify, render_template, jsonify
import KEM
from flask_mysqldb import MySQL
import hashlib, pickle
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

service_encdec = Flask(__name__)


# load database configuration
def load_mysql_config(filename="./db_config.json"):
    with open(filename) as config_file:
        config = json.load(config_file)
    return config

#Load config database
mysql_config=load_mysql_config()

print(mysql_config["host"])
# config
service_encdec.config["MYSQL_HOST"] = mysql_config["host"]
service_encdec.config["MYSQL_USER"] = mysql_config["user"]
service_encdec.config["MYSQL_PASSWORD"] = mysql_config["password"]
service_encdec.config["MYSQL_DB"] = mysql_config["database"]

# Initialize Data
mysql = MySQL(service_encdec)

key_timestamp= None
KEY_TIMEOUT_GENERATE=360
KEY_TIMEOUT_ENC_DEC=3600

@service_encdec.route("/key_generation", methods=["POST"])
def key_generation():

    #get public client key
    public_clientKey= request.json.get('ek')
    ek_client = KEM.fromPEM(public_clientKey)
    K, cipher = KEM.ml_kem_encaps(ek_client)
    #create random symmetric key with public client key

    print(public_clientKey)
    publicKey, privateKey = KEM.k_pke_keygen()
    key_timestamp=time.time()

    cur = mysql.connection.cursor()

    publicKey_pem = KEM.dktoPEM(publicKey)
    privateKey_pem = KEM.dktoPEM(privateKey)

    result = cur.execute(
        "insert into key_management (private_key, shared_key, time_stamp) values (%s, %s, %s)", 
        (privateKey_pem, K.hex(), key_timestamp,)
        ) 
    if result < 0:
        return "error key generation", 500

    result = cur.execute("select * from key_management where private_key=%s", (privateKey_pem,)) 
    if  result <0: 
        return "error", 500
    row=cur.fetchone()

    payload = {
        'ek' : publicKey_pem,
        'c' : cipher.hex(),
        'id' : row[0]
    }

    mysql.connection.commit()
    cur.close()

    return jsonify(payload), 201

@service_encdec.route("/decrypt_password", methods=["POST"])
def decrypt_password():
    data=request.get_json()
    id= data["id"]
    encrypted_password=data["password"]

    cur= mysql.connection.cursor()
    cur.execute(
        f"select shared_key from key_management where id=%s", (id,)
    )
    session = cur.fetchone()
    if not session:
        return jsonify({'error': 'Session not found'}), 404

    K= bytes.fromhex(session[0])
    print(f"K: {K.hex()}")
    cipher=bytes.fromhex(encrypted_password)
    print(f"Cipher: {encrypted_password}")
    temp= KEM.k_pke_decrypt(K,cipher)
    dercypted_password= temp.decode('utf-8')
    print(dercypted_password)
    
    payload= {
        "id" : id,
        "username" : data["username"],
        "password" : dercypted_password
    }

    return jsonify(payload), 201

@service_encdec.route("/remove/<int:id>", methods=["DELETE"])
def remove(id):

    cur = mysql.connection.cursor()
    cur.execute(f"select * from key_management where id = %s", (id,))
    session = cur.fetchone()
    if not session:
        return "ID Session not found", 404

    # Delete the session
    cur.execute(f"delete from key_management where id = %s", (id,)) 
    mysql.connection.commit()
    cur.close()
    # Done
    
    return f"Deleted successfully session {id}", 200

if __name__ == "__main__":
    service_encdec.run(host="0.0.0.0", port=2000, debug=True)