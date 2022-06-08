from flask import Flask, jsonify, request, make_response, redirect
from jsonschema import validate, ValidationError
from pymongo import MongoClient, DESCENDING
from bson.json_util import dumps
import jwt
from datetime import datetime, timedelta
import hashlib
from functools import wraps
import logging
import os
import json
import requests
import statusboard as stb
import configparser
from alike_mail import *

logging.basicConfig(level=logging.DEBUG)
app = Flask(__name__)

JWT_SECRET=""
EXP_TOKEN = int(os.environ['EXP_TOKEN'])
NAME_SERVICE = os.environ['NAME_SERVICE']
DB_ENDPOINT = 'alike-mongodb'
DB_PORT = int(os.environ['DB_PORT'])
config = configparser.ConfigParser()
config.read('/run/secrets/secret')
JWT_SECRET = config['AUTH']['JWT_SECRET']
app.logger.info(f"EXPIRATION: {EXP_TOKEN}")
app.logger.info(f"DB CONNECTED: {DB_ENDPOINT}")


schema = {
    "type":"object",
    "properties": {
        "username": {
            "type":"string",
            "pattern":'^[a-zA-Z0-9]([._-](?![._-])|[a-zA-Z0-9]){3,18}[a-zA-Z0-9]$'
            },
        "password": {
            "type":"string",
            "pattern":'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,15}$'
            },
        "email": {
            "type": "string",
            "pattern": '^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$'
        },        "bio": {"type": "string"}
    }
}

def is_valid(exp):
        app.logger.info(datetime.utcnow().strftime('%s'))
        if (exp == 'undefined' or exp == 'null' or int(exp) > int(datetime.utcnow().strftime('%s'))):
            return True
        else:
            return False

def generate_url(user):
        token = jwt.encode({
                'email': user['email'],
                'exp' : datetime.utcnow() + timedelta(minutes = EXP_TOKEN)
        }, JWT_SECRET)
        return "http://localhost:2000/validate?token=" + token

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
            "following": [],
            "saved": [],
            "verified": False,
            "disabled": False,
            "created_at":datetime.now().strftime("%Y-%m-%d"),
            "updated_at":datetime.now().strftime("%Y-%m-%d")
        }


        validate(instance=new_user, schema=schema,)

        new_user['password'] = hashed_password
        with MongoClient(DB_ENDPOINT, DB_PORT) as client:
             db = client.users
             db.user.insert_one(new_user);
             activation_url = generate_url({'email':new_user['email']})
             request_confirmation(new_user['email'], new_user['username'], activation_url)
             return  make_response(jsonify({'message' : 'user added'}), 201)
     
    except ValidationError as error:
         logging.info(error)
         return  make_response(jsonify({'error' : 'validation error'}), 400)

    except Exception as error:
        logging.info(error)
        return make_response(jsonify({'error' : str(error)}), 500)

@app.route('/validate', methods=["GET"])
def activate_user():
        try:
                token = request.args.get("token", default="", type=str)
                decoded_token = jwt.decode(token, JWT_SECRET, algorithms="HS256")
                query = {"email":decoded_token['email']}
                update_query = {"$set": {"email":decoded_token['email'], "verified":True,
                                         "updated_at":datetime.now().strftime("%Y-%m-%d")}}

                with MongoClient(DB_ENDPOINT, DB_PORT) as client:
                        db = client.users
                        db.user.update_one(query, update_query)
                        return redirect("http://www.example.com", code=200)

        except Exception as error:
                return make_response(jsonify({'error' : str(error)}), 500)

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
                }, JWT_SECRET)
                return make_response(jsonify({'token' : token}), 201)
            else:
                return jsonify({"error" : "user or password incorrect"})

    except ValidationError as error:
        logging.info(error)
        return make_response(jsonify({'error' : 'validation error'}), 500)

    except Exception as error:
        logging.info(error)
        return make_response(jsonify({'error' : str(error)}), 500)
    
@app.route('/auth', methods=["GET"])
def verify_token():
    stb.notify(NAME_SERVICE)  
    token = request.headers.get('Authorization')
    app.logger.info(token)
    
    try:
        decoded_token = jwt.decode(token, JWT_SECRET, algorithms="HS256")
        app.logger.info(decoded_token)

        if is_valid(decoded_token['exp']):
                fresh_token = jwt.encode({
                        'public_id': decoded_token['public_id'],
                        'exp' : datetime.utcnow() + timedelta(minutes = EXP_TOKEN)
                }, JWT_SECRET)
                return make_response(jsonify({'public_id' : decoded_token['public_id'],
                                              'token':fresh_token}), 200)
        else:
             return make_response(jsonify({'error' : 'unauthorized'}), 401)

    except Exception as error:
        app.logger.error(error)
        return make_response(jsonify({'error' : 'unauthorized'}), 401)


@app.route('/password_token', methods=["GET"])
def password_token():
    stb.notify(NAME_SERVICE)  
    try:
        #First type of token, recover by email
        if 'email' in request.json:
            user = {
                "email": request.json['email'],
            }
            validate(instance=user, schema=schema,)
     
            with MongoClient(DB_ENDPOINT, DB_PORT) as client:
                db = client.users
                query = {"email":user['email']}
                query_result = db.user.find_one(query)
               
        #Second type, recover with last password
        elif 'password' in request.json:
            token = request.headers.get('Authorization')
            decoded_token = jwt.decode(token, JWT_SECRET, algorithms="HS256")
            
            with MongoClient(DB_ENDPOINT, DB_PORT) as client:
                db = client.users
                query = {"username":decoded_token['public_id']}
                query_result = db.user.find_one(query)
                
            m = hashlib.new('sha256')
            m.update(request.json['password'].encode('utf-8'))
            hashed_password = m.hexdigest()
            
            if query_result['password'] != hashed_password :
                return make_response(jsonify({'message' : 'unauthorized'}), 401)
        else:
            return make_response(jsonify({'message' : 'forbidden'}), 403)

        token = jwt.encode({
            'email': query_result['email'],
            'exp' : datetime.utcnow() + timedelta(minutes = EXP_TOKEN),
            'old_password': query_result['password']
        }, JWT_SECRET)

        if 'email' in request.json:
                change_password_url = "http://localhost:2000/reset_password?token="+token
                request_password(query_result['email'], change_password_url)
         
        return make_response(jsonify({'token' : token}), 201)
                      
    except ValidationError as error:
        logging.info(error)
        return make_response(jsonify({'error': 'validation error'}), 400)

    except Exception as error:
        logging.info(error)
        return make_response(jsonify({'error': str(error)}), 400)
    
@app.route('/change_password', methods=["POST"])
def change_password():
    stb.notify(NAME_SERVICE)  

    token = request.headers.get('Authorization')

    user = {
         "password": request.json['password'],
    }

    validate(instance=user, schema=schema,)

    decoded_token = jwt.decode(token, JWT_SECRET, algorithms="HS256")
     
    with MongoClient(DB_ENDPOINT, DB_PORT) as client:
        db = client.users
        query = {"email":decoded_token['email']}
        query_result = db.user.find_one(query)

        if not query_result:
                return make_response(jsonify({'error' : 'not found'}), 404)

        elif query_result['password'] == decoded_token['old_password']:        
                m = hashlib.new('sha256')
                m.update(request.json['password'].encode('utf-8'))
                hashed_password = m.hexdigest()

                if hashed_password == query_result['password']:
                        return make_response(jsonify({'error' : 'cannot use the same password'}), 403)

                update_query = {"$set": {"email":decoded_token['email']
                                         , "password": hashed_password,
                                         "updated_at":datetime.now().strftime("%Y-%m-%d")}}

                db.user.update_one(query, update_query)
                return make_response(jsonify({'message' : 'password updated'}), 200)

        else:
                return make_response(jsonify({'error' : 'token invalid'}), 403)


@app.route('/user/<username>', methods=["GET"])     
def show_profile(username):
        
        with MongoClient(DB_ENDPOINT, DB_PORT) as client:
                db = client.users
                query = {"username":username}
                query_result = db.user.find_one(query)

                if query_result:
                        user = {
                                "username": query_result['username'],
                                "bio": query_result['bio'],
                                "following": query_result['following'],
                                "verified": query_result['verified']
                                }
                        return make_response(jsonify(user), 200)
                else:
                        return make_response(jsonify({'error' : 'user not found'}), 404)

                        
@app.route('/user', methods=["PUT"])     
def edit_profile():
    stb.notify(NAME_SERVICE)  
    token = request.headers.get('Authorization')

    try:
        decoded_token = jwt.decode(token, JWT_SECRET, algorithms="HS256")
        app.logger.info(decoded_token)
        username = decoded_token['public_id']

        if not is_valid(decoded_token['exp']):
                return make_response(jsonify({'error' : 'unauthorized'}), 401)

        
    except Exception as error:
        app.logger.error(error)
        return make_response(jsonify({'error' : 'unauthorized'}), 401)

    
    profile = {
        "username":username
    }
    edited_profile = {"updated_at":datetime.now().strftime("%Y-%m-%d")}
    try:

        if 'username' in request.json:
            edited_profile['username'] = request.json['username']
            token = jwt.encode({
                'public_id': edited_profile['username'],
                'exp' : datetime.utcnow() + timedelta(minutes = EXP_TOKEN)
            }, JWT_SECRET)
            
            #update messages
            with MongoClient(DB_ENDPOINT, DB_PORT) as client:
                    db = client.messenger
                    query = {"from": username}
                    update_query = {"$set": {"from":  edited_profile['username']}}
                    db.message.update_one(query, update_query)
                    query = {"to": username}
                    update_query = {"$set": {"to":  edited_profile['username']}}
                    db.message.update_one(query, update_query)
                    
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
        return make_response(jsonify({'error': 'validation error'}), 400)

    except Exception as error:
        logging.info(error)
        return make_response(jsonify({'error' : str(error)}), 401)

@app.route('/user', methods=["DELETE"])     
def delete_profile():
    stb.notify(NAME_SERVICE)  
    token = request.headers.get('Authorization')
     
    try:
        decoded_token = jwt.decode(token, JWT_SECRET, algorithms="HS256")
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
            return make_response(jsonify({'error' : 'unauthorized'}), 401)
        
    except Exception as error:
        app.logger.error(error)
        return make_response(jsonify({'error' : 'error deleting user'}), 500)


@app.route('/search/<username>', methods=["GET"])     
def search_profile(username):

        with MongoClient(DB_ENDPOINT, DB_PORT) as client:
                db = client.users
                query = {"username":{'$regex':'^'+username, "$options": "-xi"}}
                projection = {"_id": 0, "username": 1, "bio": 1, "disabled":1}
                query_result = db.user.find(query, projection)
                if query_result:
                        return make_response(dumps(query_result), 200)

                return make_response(jsonify({"error":"user not found"}), 404)

@app.route('/follow/<username>', methods=["POST"])     
def follow(username):

        token = request.headers.get('Authorization')
        decoded_token = jwt.decode(token, JWT_SECRET, algorithms="HS256")
        user = decoded_token['public_id']  
        
        if user == username:
                return make_response({"message":"cannot follow yourself"}, 400)

        with MongoClient(DB_ENDPOINT, DB_PORT) as client:
                db = client.users
                query = {"username":user}
                query_result = db.user.find_one(query)
                
                if not db.user.find_one({"username":username}):
                        return make_response(jsonify({"error":"user not found"}), 404)

                following =  query_result['following']
                
                if username in following:
                        return make_response(jsonify({"message":"already followed"}), 200)
   
                update_query = {"$push": {"following":username}}
                db = client.users
                db.user.update_one(query, update_query)
                return make_response(jsonify({"message":"followed"}), 200)

@app.route('/follow/<username>', methods=["DELETE"])     
def unfollow(username):
        token = request.headers.get('Authorization')
        decoded_token = jwt.decode(token, JWT_SECRET, algorithms="HS256")
        user = decoded_token['public_id']  
        
        if user == username:
                return make_response({"error": "cannot unfollow yourself"}, 400)

        with MongoClient(DB_ENDPOINT, DB_PORT) as client:
                db = client.users
                query = {"username":user}
                update_query = {"$pull": {"following":username}}
                db.user.update_one(query, update_query)
                return make_response(jsonify({"message": "unfollowed"}), 200)

        return make_response(jsonify({"error":"could not unfollow"}), 500)

@app.route('/save/<id_list>', methods=["POST"])     
def save(id_list):
        token = request.headers.get('Authorization')
        decoded_token = jwt.decode(token, JWT_SECRET, algorithms="HS256")
        user = decoded_token['public_id']

        with MongoClient(DB_ENDPOINT, DB_PORT) as client:
                db = client.users
                query = {"username":user}
                update_query = {"$push": {"saved":id_list}}
                db.user.update_one(query, update_query)
                return make_response(jsonify({"message":"saved"}), 200)

        return make_response(jsonify({"error":"could not save"}), 500)

@app.route('/save/<id_list>', methods=["DELETE"])     
def unsave(id_list):
        token = request.headers.get('Authorization')
        decoded_token = jwt.decode(token, JWT_SECRET, algorithms="HS256")
        user = decoded_token['public_id']

        with MongoClient(DB_ENDPOINT, DB_PORT) as client:
                db = client.users
                query = {"username":user}
                update_query = {"$pull": {"saved":id_list}}
                res_query = db.user.update_one(query, update_query)
                if res_query.modified_count:
                        return make_response(jsonify({"message":"removed from saved list"}), 200)

        return make_response(jsonify({"error":"could not removed"}), 500)

def init_database():
    with MongoClient(DB_ENDPOINT, DB_PORT) as client:
        db = client.users
        db.user.create_index([("email", DESCENDING)], unique=True) 
        db.user.create_index([("username", DESCENDING)], unique=True) 
        
if __name__ =='__main__':
    init_database()
    app.run(host='0.0.0.0', debug = True)  
