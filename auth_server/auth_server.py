import jwt, datetime, os, json
from flask import Flask, request, jsonify
from flask_mysqldb import MySQL 

auth_server = Flask(__name__)
# jwt_secret = '7b8c6ef87a5d4e3e2b1a0d9c8b7a6f5e'

#function loadconfig
def load_mysql_config(filename="./db_config.json"):
    with open(filename) as config_file:
        config = json.load(config_file)
    return config

#Load config database
mysql_config=load_mysql_config()

# config
auth_server.config["MYSQL_HOST"] = mysql_config["host"]
auth_server.config["MYSQL_USER"] = mysql_config["user"]
auth_server.config["MYSQL_PASSWORD"] = mysql_config["password"]
auth_server.config["MYSQL_DB"] = mysql_config["database"]

# Initialize mysql
mysql = MySQL(auth_server)
@auth_server.route("/")
def index():
    return "Welcome!"

# Routes
@auth_server.route("/signup", methods=['POST'])
def signup():
    auth = request.authorization
    if not auth:
        return "missing information", 400
    
    # check if existed  
    cur = mysql.connection.cursor()
    result = cur.execute(
        "SELECT * FROM users WHERE username=%s", (auth.username,)
    )
    if(result >0 ):
        return "Account existed!", 401
        
    #insert into database
    result = cur.execute(
        "insert into users (username, password, rule) values (%s, %s, %s)", (auth.username,auth.password,0,)
    )
    mysql.connection.commit()

    if result > 0:
        return "Sign Up successfully!", 201
    return "Failed to Register", 500

@auth_server.route("/login", methods=["POST"])
def login():
    auth = request.authorization
    # print(auth)
    if not auth:
        return "Missing information", 400

    # check db for username and password
    cur = mysql.connection.cursor()
    result = cur.execute(
        "SELECT * FROM users WHERE username=%s", (auth.username,)
    )

    if result > 0:
        user_row = cur.fetchone()
        id =  user_row[0]
        username = user_row[1]
        password = user_row[2]
        rule=user_row[3]
        
        if auth.username != username or auth.password != password:
            return "Username or Password not fit!", 401
        else:
            data={
                "id" : id,
                "username": username
            }
            return jsonify(data), 201
    else:
        return "User doesn't exist!", 401

context = ('./certificate.crt', './private_key.key')

if __name__ == "__main__":
    auth_server.run(host="0.0.0.0", port=5000, debug=True)
