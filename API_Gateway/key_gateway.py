import os, requests, json
from flask import render_template, jsonify
import hashlib

def create_session(request):
    if request is None:
        return None, ("Error", 500)
    
    data=request.get_json()
    
    headers = {
        "Content-Type": "application/json"
    }

    response = requests.post(
        f"http://127.0.0.1:2000/key_generation", data=json.dumps(data), headers=headers
    )

    if response.status_code == 201:
        return response.text, None
    else:
        return None, (response.text, response.status_code)

#check session theo use K decrypt pasword
def check_session(request):
    data=request.get_json()
    headers = {
        "Content-Type": "application/json"
    }

    response = requests.post(
        f"http://127.0.0.1:2000/decrypt_password",
         data=json.dumps(data), headers=headers
    )

    if response.status_code==201:
        return response.text, None
    else:
        return None, (response.text, response.status_code)

def delete_session(request):
    data=request.get_json()
    id=data["id"]
    
    response = requests.delete(
    f"http://127.0.0.1:2000/remove/{id}"
    )

    print(f"Delete session: {response.text}")
    if response.status_code == 200:
        return response.text, None
    else:
        return None, (response.text, response.status_code)



