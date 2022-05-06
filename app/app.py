from flask import Flask, jsonify, request, make_response
from pymongo import MongoClient
import jwt
from datetime import datetime, timedelta
import hashlib
from functools import wraps
import logging
import os

client = MongoClient('mongodb:27017')
logging.basicConfig(level=logging.DEBUG)
app = Flask(__name__)

SECRET_KEY = os.environ['SECRET_KEY']
EXP_TOKEN = int(os.environ['EXP_TOKEN'])
app.logger.info(f"SECRET KEY: {SECRET_KEY} EXPIRATION: {EXP_TOKEN}")

@app.route('/signup', methods=["POST"])
def signup():
    try:
        m = hashlib.new('sha256')
        m.update(request.json['password'].encode('utf-8'))
        hashed_password = m.hexdigest()
        new_user = {
            "username": request.json['username'],
            "password": hashed_password,
            "email": request.json['email'],
            "verified": False
        }

        with MongoClient('mongodb:27017') as client:
            db = client.users
            db.user.insert_one(new_user);
            return jsonify({'message':'user added'})
    except Exception as error:
        logging.info(error)
        return 'ada'
    
@app.route('/signin', methods=["POST"])
def signin():
    app.logger.info(request.json)
    m = hashlib.new('sha256')
    m.update(request.json['password'].encode('utf-8'))
    hashed_password = m.hexdigest()
    user = {
        "username": request.json['username'],
        "password": request.json['password'],
    }

    with MongoClient('mongodb:27017') as client:
        db = client.users
        query = {"username":user['username'], "password": hashed_password}

        if db.user.find_one(query):
            token = jwt.encode({
                'public_id': user['username'],
                'exp' : datetime.utcnow() + timedelta(minutes = EXP_TOKEN)
                }, SECRET_KEY)
            return make_response(jsonify({'token' : token}), 201)
        else:
            return jsonify({"message":"usuario o contraseña incorrectos"})

@app.route('/auth', methods=["GET"])
def verify_token():
    def is_valid(exp):
        app.logger.info(datetime.utcnow().strftime('%s'))
        if (exp == 'undefined' or exp == 'null' or int(exp) > int(datetime.utcnow().strftime('%s'))):
            return True
        else:
            return False
        
    verified = {
        'public_id': request.json['public_id'],
        'token': request.json['token'],
    }
    
    try:
        decoded_token = jwt.decode(verified['token'], SECRET_KEY, algorithms="HS256")
        app.logger.info(decoded_token)
        if (decoded_token['public_id'] == verified['public_id']) and is_valid(decoded_token['exp']):
            return make_response(jsonify({'public_id' : decoded_token['public_id']}), 200)
        else:
             return make_response(jsonify({'message' : 'unauthorized'}), 401)
    except Exception as error:
        app.logger.error(error)
        return make_response(jsonify({'message' : 'unauthorized'}), 401)
                                   
def init_database():
    pass

if __name__ =='__main__':  
    app.run(host='0.0.0.0', debug = True)  
