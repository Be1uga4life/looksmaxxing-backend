import os
import re
import io
import zlib
from werkzeug.utils import secure_filename
from flask import Response
from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session ,url_for
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
import face_recognition
from PIL import Image
from base64 import b64encode, b64decode
import re
from flask import Flask, request, jsonify, redirect, session, render_template
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from flask import Blueprint, request, jsonify, current_app, Response

import functools
from functools import wraps

from flask import Flask
from flask_cors import CORS


app = Flask(__name__)
CORS(app)


@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

db = SQL("sqlite:///data.db")

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if "token" not in session:
            return redirect("/login")
        token = session["token"]
        try:
            data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            user_id = data["user_id"]
            user = db.execute("SELECT * FROM users WHERE id = :user_id", user_id=user_id).fetchone()

            if not user:
                return "User Not Found"

            return view(user, **kwargs)
        except jwt.ExpiredSignatureError:
            return render_template("login.html", message="Expired token")
        except jwt.InvalidTokenError:
            return render_template("login.html", message="Invalid token")
    return wrapped_view


@app.route("/")
@login_required
def home():
    return redirect("/home")

@app.route("/home")
@login_required
def index():
    return render_template("index.html")


import jwt
from datetime import datetime, timedelta

@app.route("/login", methods=["POST"])
def login():
    app.config["SECRET_KEY"] = "password"

    data = request.get_json()

    input_username = data.get("username")
    input_password = data.get("password")

    # Query database for username
    users = db.execute("SELECT * FROM users WHERE username = :username", username=input_username)

    # Check if there are any users with the provided username
    if not users:
        return jsonify("User Not Found!")

    # Check each user's password
    for user in users:
        if check_password_hash(user["hash"], input_password):
            # Set the expiration time for the token (e.g., 1 hour from now)
            expiration_time = datetime.utcnow() + timedelta(hours=1)
            # Encode the token with the expiration time
            token = jwt.encode({"user_id": str(user["id"]), "exp": expiration_time}, current_app.config["SECRET_KEY"], algorithm="HS256")
            session["token"] = token 
            return jsonify({"message": "Login Successful!", "token": token})
    
    return jsonify("Invalid Username or Password")





@app.route("/logout")
def logout():
    """Log user out"""

    session.pop("token", None)

    # Redirect user to login form
    return redirect("/")



@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == "POST":

        data = request.get_json()

        input_username = data.get("username")
        input_password = data.get("password")
        input_confirmation = data.get("confirmation")

        # Ensure username was submitted
        if not input_username:
            return "Please input Username!"

        # Ensure password was submitted
        elif not input_password:
            return "Please input Password!"

        # Ensure passwsord confirmation was submitted
        elif not input_confirmation:
            return "Please submit password confirmation!"

        elif not input_password == input_confirmation:
            return "Passwords aren't matching!"

        # Query database for username
        username = db.execute("SELECT username FROM users WHERE username = :username",
                              username=input_username)

        # Ensure username is not already taken
        if len(username) == 1:
            return "Username is already taken"

        # Query database to insert new user
        else:
            new_user = db.execute("INSERT INTO users (username, hash) VALUES (:username, :password)",
                                  username=input_username,
                                  password=generate_password_hash(input_password, method="pbkdf2:sha256", salt_length=8),)

            if new_user:
                # Keep newly registered user logged in
                session["user_id"] = new_user

            # Flash info for the user
            flash(f"Registered as {input_username}")

            # Redirect user to homepage
            return "Signup Successful!"

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")




@app.route("/facereg", methods=["POST"])
def facereg():
    app.config["SECRET_KEY"] = "password"
    
    encoded_image = request.form.get("image")
    username = request.form.get("username")
    name = db.execute("SELECT * FROM users WHERE username = :username", username=username)

    
    if len(name) != 1:
        response = jsonify({"message": "Either name not provided, or invalid"})
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response

    id_ = name[0]['id'] 
    
    encoded_image = encoded_image.split(',')
    encoded_image = encoded_image[1].strip()

    decoded_data = b64decode(encoded_image)
    
    new_image_handle = open('./static/face/'+str(id_)+'.jpg', 'wb')
    
    new_image_handle.write(decoded_data)
    new_image_handle.close()
    
    try:
        image_of_bill = face_recognition.load_image_file('./static/face/'+str(id_)+'.jpg')
    except:
        response = jsonify({"message": "No Face Recognition setup yet"})
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response

    bill_face_encoding = face_recognition.face_encodings(image_of_bill)[0]

    unknown_image = face_recognition.load_image_file('./static/face/'+str(id_)+'.jpg')
    try:
        unknown_face_encoding = face_recognition.face_encodings(unknown_image)[0]
    except:
        response = jsonify({"message": "Not clear face"})
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response

    results = face_recognition.compare_faces([bill_face_encoding], unknown_face_encoding)

    if results[0]:
        response = jsonify({"message": "Authentication Succesful"})
        response.headers.add('Access-Control-Allow-Origin', '*')


        first_item = name[0]
        user_id = first_item['id']

        expiration_time = datetime.utcnow() + timedelta(hours=1)
        token = jwt.encode({"user_id": str(user_id), "exp": expiration_time}, current_app.config["SECRET_KEY"], algorithm="HS256")
        session["token"] = token 
        return jsonify({"message": "Login Successful!", "token": token})
    else:
        response = jsonify({"message": "Failed Authentication"})
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response

    response = jsonify({"message": "Something went wrong"})
    response.headers.add('Access-Control-Allow-Origin', '*')
    return response

if __name__ == "__main__":
    app.run(debug=True)

