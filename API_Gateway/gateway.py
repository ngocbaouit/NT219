import os, json, requests
from flask import Flask, request, jsonify, render_template
import auth_gateway
import key_gateway
from flask_mysqldb import MySQL
import hashlib

gateway = Flask(__name__)


# load database configuration
def load_mysql_config(filename="./db_config.json"):
    with open(filename) as config_file:
        config = json.load(config_file)
    return config

#Load config database
mysql_config=load_mysql_config()

print(mysql_config["host"])
# config
gateway.config["MYSQL_HOST"] = mysql_config["host"]
gateway.config["MYSQL_USER"] = mysql_config["user"]
gateway.config["MYSQL_PASSWORD"] = mysql_config["password"]
gateway.config["MYSQL_DB"] = mysql_config["database"]

# Initialize Data
mysql = MySQL(gateway)

@gateway.route('/')
def hello():
    return 'Hello'

@gateway.route("/session", methods=["POST"])
def session_signup():
    # Bên nhận request public key từ server
    print(request)
    result, err =key_gateway.create_session(request)
    if not err:
        return result, 201
        
    return err


@gateway.route("/signup", methods=["POST"])
def signup():
    return_data, err = key_gateway.check_session(request)
    result, err = auth_gateway.signup(return_data)
    res1, err1 = key_gateway.delete_session(request)
    if not err and not err1:
        return result, 201
    return "Failed to signup", 500
    
@gateway.route("/login")
def show_login():
    return render_template('login.html')

@gateway.route("/login", methods=["POST"])
def login():
    #Get session_id and username
    data= request.get_json()
    session_id = data["id"]
    username = data["username"]
    # Check already login
    cur= mysql.connection.cursor()
    res=cur.execute(
        f"select * from session_management where username=%s",(username,)
    )
    print(res)
    if res>0:
        res1, err1 = key_gateway.delete_session(request)
        return "Already logined!", 301

    # Check session_id to use the right K to decrypt password
    return_data, err = key_gateway.check_session(request)
    result, err = auth_gateway.login(return_data)
    if not err:
        input= json.loads(result)
        username = input["username"]
        user_id =  input["id"]
        res=cur.execute(
            f"insert into session_management (session_id, user_id, username) values(%s, %s, %s) ", 
            (session_id, user_id, username, )
        )
        mysql.connection.commit()
        return "Login successfully!", 201

    mysql.connection.commit()
    cur.close()
    return "Failed to login!", 500

    
@gateway.route("/logout/<int:id>", methods=["POST"])
def logout(id):
    cur= mysql.connection.cursor()
    res=cur.execute(
        f"select * from session_management where session_id=%s",(id,)
    )
    res_del=None
    if(res>0):
        res_del = cur.execute(
            f"delete from session_management where session_id=%s", (id,)
        )
        mysql.connection.commit()
    mysql.connection.commit()
    cur.close()

    response = requests.delete(
        f"http://127.0.0.1:2000/remove/{id}",
    )
    
    print(response.text)

    if res > 0:
        return "Log out successfully!", 200
    return "Failed to log out!", 404


context = ('./certificate.crt', './private_key.key')

if __name__ == "__main__":
    gateway.run(host="0.0.0.0", port=8000, debug=True)