from flask import Flask, jsonify, request, make_response
from pymongo import MongoClient
import jwt
from datetime import datetime, timedelta
import hashlib
from functools import wraps
import logging
import os
import json
import requests
import statusboard as stb


logging.basicConfig(level=logging.DEBUG)
app = Flask(__name__)

SECRET_KEY = os.environ['SECRET_KEY']
EXP_TOKEN = int(os.environ['EXP_TOKEN'])
NAME_SERVICE = os.environ['NAME_SERVICE']
DB_ENDPOINT = 'alike-mongodb'
DB_PORT = int(os.environ['DB_PORT'])


app.logger.info(f"SECRET KEY: {SECRET_KEY} EXPIRATION: {EXP_TOKEN}")
app.logger.info(f"DB CONNECTED: {DB_ENDPOINT}")

@app.route('/signup', methods=["POST"])
def signup():
    stb.notify(NAME_SERVICE)
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

        with MongoClient(DB_ENDPOINT, DB_PORT) as client:
            db = client.users
            db.user.insert_one(new_user);
            return jsonify({'message':'user added'})

    except Exception as error:
        logging.info(error)
        return 'error'
    
@app.route('/signin', methods=["POST"])
def signin():
    stb.notify(NAME_SERVICE)
    app.logger.info(request.json)
    m = hashlib.new('sha256')
    m.update(request.json['password'].encode('utf-8'))
    hashed_password = m.hexdigest()
    user = {
        "username": request.json['username'],
        "password": request.json['password'],
    }
    
    with MongoClient(DB_ENDPOINT, DB_PORT) as client:
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
    stb.notify(NAME_SERVICE)

    def is_valid(exp):
        app.logger.info(datetime.utcnow().strftime('%s'))
        if (exp == 'undefined' or exp == 'null' or int(exp) > int(datetime.utcnow().strftime('%s'))):
            return True
        else:
            return False
        
  
    token = request.headers.get('Authorization')
    
    app.logger.info(token)
    try:
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms="HS256")
        app.logger.info(decoded_token)
        if is_valid(decoded_token['exp']):
            return make_response(jsonify({'public_id' : decoded_token['public_id']}), 200)
        else:
             return make_response(jsonify({'message' : 'unauthorized'}), 401)
    except Exception as error:
        app.logger.error(error)
        return make_response(jsonify({'message' : 'unauthorized'}), 401)


@app.route('/recover_password', methods=["GET"])
def recover_password():
     user = {
        "email": request.json['email'],
     }
    
     with MongoClient(DB_ENDPOINT, DB_PORT) as client:
         db = client.users
         query = {"email":user['email']}
         query_result = db.user.find_one(query)
        
         if query_result :
             token = jwt.encode({
                 'email': user['email'],
                 'exp' : datetime.utcnow() + timedelta(minutes = EXP_TOKEN),
                 'old_password': query_result['password']
             }, SECRET_KEY)
             return make_response(jsonify({'token' : token}), 201)
         else:
             return jsonify({"message":"email no encontrado"})

@app.route('/change_password', methods=["POST"])
def change_password():

    token = request.headers.get('Authorization')

    user = {
         "password": request.json['password'],
    }
     
    decoded_token = jwt.decode(token, SECRET_KEY, algorithms="HS256")

    m = hashlib.new('sha256')
    m.update(request.json['password'].encode('utf-8'))
    hashed_password = m.hexdigest()
    if hashed_password == decoded_token['old_password']:
        return jsonify({"message":"cannot use the same password"})
     
    with MongoClient(DB_ENDPOINT, DB_PORT) as client:
        db = client.users
        query = {"email":decoded_token['email']}
        query_result = db.user.find_one(query)

        if not query_result:
            return make_response(jsonify({'message' : 'not found'}), 404)

        elif query_result['password'] == decoded_token['old_password']:
            update_query = {"$set": {"email":decoded_token['email']
                                     , "password": hashed_password}}
            db.user.update_one(query, update_query)
            return jsonify({"message":"usuario actualizado"})

        else:
            return make_response(jsonify({'message' : 'token invalid'}), 403)

         
            
def init_database():
    pass

if __name__ =='__main__':  
    app.run(host='0.0.0.0', debug = True)  
