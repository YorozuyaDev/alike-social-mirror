from flask import Flask, jsonify, request, make_response
from jsonschema import validate, ValidationError
from pymongo import MongoClient, DESCENDING
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


schema = {
    "type":"object",
    "properties": {
        "username": {"type": "string"},
        "password": {
            "type":"string",
            "pattern":'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,15}$'
            },
        "email": {
            "type": "string",
            "pattern": '^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$'
        },
        "bio": {"type": "string"}
    }
}

def is_valid(exp):
        app.logger.info(datetime.utcnow().strftime('%s'))
        if (exp == 'undefined' or exp == 'null' or int(exp) > int(datetime.utcnow().strftime('%s'))):
            return True
        else:
            return False

        
@app.route('/signup', methods=["POST"])
def signup():
    stb.notify(NAME_SERVICE)
    try:
        m = hashlib.new('sha256')
        m.update(request.json['password'].encode('utf-8'))
        hashed_password = m.hexdigest()
        new_user = {
            "username": request.json['username'],
            "password": request.json['password'],
            "email": request.json['email'],
            "bio": request.json['bio'],
            "verified": False,
            "disabled": False,
        }

        validate(instance=new_user, schema=schema,)

        new_user['password'] = hashed_password
        with MongoClient(DB_ENDPOINT, DB_PORT) as client:
             db = client.users
             db.user.insert_one(new_user);
             return jsonify({'message':'user added'})

    except ValidationError as error:
         logging.info(error)
         return  jsonify({'message':'error de validación'})

    except Exception as error:
        logging.info(error)
        return  jsonify({'message':'Error: '+ str(error)})
         
@app.route('/signin', methods=["POST"])
def signin():
    try:
        stb.notify(NAME_SERVICE)
        app.logger.info(request.json)
        m = hashlib.new('sha256')
        m.update(request.json['password'].encode('utf-8'))
        hashed_password = m.hexdigest()
        user = {
            "username": request.json['username'],
            "password": request.json['password'],
        }
        validate(instance=user, schema=schema,)

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

    except ValidationError as error:
        logging.info(error)
        return  jsonify({'message':'error de validación'})

    except Exception as error:
        logging.info(error)
        return  jsonify({'message':'Error: '+error})

    
@app.route('/auth', methods=["GET"])
def verify_token():
    stb.notify(NAME_SERVICE)  
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
    stb.notify(NAME_SERVICE)  
    try:
        user = {
            "email": request.json['email'],
        }
        validate(instance=user, schema=schema,)
     
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
            
    except ValidationError as error:
        logging.info(error)
        return  jsonify({'message':'error de validación'})

    except Exception as error:
        logging.info(error)
        return  jsonify({'message':'Error: '+error})
    
@app.route('/change_password', methods=["POST"])
def change_password():
    stb.notify(NAME_SERVICE)  
    token = request.headers.get('Authorization')

    user = {
         "password": request.json['password'],
    }

    validate(instance=user, schema=schema,)

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

@app.route('/edit_profile', methods=["PUT"])     
def edit_profile():
    stb.notify(NAME_SERVICE)  
    token = request.headers.get('Authorization')

    try:
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms="HS256")
        app.logger.info(decoded_token)
        username = decoded_token['public_id']
        if not is_valid(decoded_token['exp']):
            return make_response(jsonify({'message' : 'unauthorized'}), 401)

    except Exception as error:
        app.logger.error(error)
        return make_response(jsonify({'message' : 'unauthorized'}), 401)

    
    profile = {
        "username":username
    }
    edited_profile = {}
    try:

        if 'username' in request.json:
            edited_profile['username'] = request.json['username']
            token = jwt.encode({
                'public_id': edited_profile['username'],
                'exp' : datetime.utcnow() + timedelta(minutes = EXP_TOKEN)
            }, SECRET_KEY)
            
        if 'bio' in request.json:
            edited_profile['bio'] = request.json['bio']

        if 'email' in request.json:
            edited_profile['email'] = request.json['email']
            edited_profile['verified'] = False

        validate(instance=edited_profile, schema=schema,)

        update_profile = {"$set": edited_profile}
        with MongoClient(DB_ENDPOINT, DB_PORT) as client:
            db = client.users
            db.user.update_one(profile, update_profile)
            return make_response(jsonify({'message':'updated user','token' : token}), 201)

               
    except ValidationError as error:
        logging.info(error)
        return  jsonify({'message':'error de validación'})

    except Exception as error:
        logging.info(error)
        return  jsonify({'message':'Error: '+error})

@app.route('/delete_profile', methods=["DELETE"])     
def delete_profile():
    stb.notify(NAME_SERVICE)  
    token = request.headers.get('Authorization')
     
    try:
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms="HS256")
        app.logger.info(decoded_token)
        username = decoded_token['public_id']
        
        if  is_valid(decoded_token['exp']):
            with MongoClient(DB_ENDPOINT, DB_PORT) as client:
                query = {"username":username}
                update_query = {"$set": {"disabled":datetime.now().strftime("%Y-%m-%d")}}
                db = client.users
                db.user.update_one(query, update_query)
                return make_response(jsonify({'message' : 'user deleted'}), 200)
        else:
            return make_response(jsonify({'message' : 'unauthorized'}), 401)
        
    except Exception as error:
        app.logger.error(error)
        return make_response(jsonify({'message' : 'error deleting user'}), 500)
    
def init_database():
    with MongoClient(DB_ENDPOINT, DB_PORT) as client:
        db = client.users
        db.user.create_index([("email", DESCENDING)], unique=True) 
        db.user.create_index([("username", DESCENDING)], unique=True) 
        
if __name__ =='__main__':
    init_database()
    app.run(host='0.0.0.0', debug = True)  
