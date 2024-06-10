import os, requests, json
from flask import render_template
import hashlib

def login(input_data):
    data = json.loads(input_data)
    username= data["username"]
    password=data["password"]
    print(username)
    print(password)

    #hash the password
    sha = hashlib.sha3_256()
    sha.update(bytes(password, "utf-8"))
    hash_pass = sha.hexdigest()

    properties = (username, hash_pass)

    response = requests.post(
        f"http://127.0.0.1:5000/login", auth=properties
    )
    
    if response.status_code == 201:
        return response.text, None
    else:
        return None, (response.text, response.status_code)
    
def signup(input_data):
    data = json.loads(input_data)
    username= data["username"]
    password=data["password"]
    print(username)
    print(password)

    #hash the passowrd
    sha = hashlib.sha3_256()
    sha.update(bytes(password, "utf-8"))
    hash_pass = sha.hexdigest()

    properties = (username, hash_pass)

    #request for register auth _ server
    response = requests.post(
        f"http://127.0.0.1:5000/signup", auth=properties
    )
    
    if response.status_code == 201:
        return response.text, None
    else:
        return None, (response.text, response.status_code)
