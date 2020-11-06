from flask import Flask, request, jsonify
from sqlalchemy.exc import IntegrityError
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
import re
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, \
    jwt_refresh_token_required, create_refresh_token, get_raw_jwt

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///twitter.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)
app.config["JWT_SECRET_KEY"] = "myawesomesecretisnevergonnagiveyouup"
app.config["JWT_BLACKLIST_ENABLED"] = True
app.config["JWT_BLACKLIST_TOKEN_CHECKS"] = ["access", "refresh"]
jwt = JWTManager(app)
CORS(app)

db = SQLAlchemy(app)

class InvalidToken(db.Model):
    __tablename__ = "invalid_tokens"
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String)

    def save(self):
        db.session.add(self)
        db.session.commit()

    @classmethod
    def is_invalid(cls, jti):
        q = cls.query.filter_by(jti=jti).first()
        return bool(q)


@jwt.token_in_blacklist_loader
def check_if_blacklisted_token(decrypted):
    jti = decrypted["jti"]
    return InvalidToken.is_invalid(jti)

@app.route("/api/checkiftokenexpire", methods=["POST"])
@jwt_required
def check_if_token_expire():
    print(get_jwt_identity())
    return jsonify({"success": True})

@app.route("/api/refreshtoken", methods=["POST"])
@jwt_refresh_token_required
def refresh():
    identity = get_jwt_identity()
    token = create_access_token(identity=identity)
    return jsonify({"token": token})

@app.route("/api/logout/access", methods=["POST"])
@jwt_required
def access_logout():
    jti = get_raw_jwt()["jti"]
    try:
        invalid_token = InvalidToken(jti=jti)
        invalid_token.save()
        return jsonify({"success": True})
    except Exception as e:
        print(e)
        return {"error": e}


@app.route("/api/logout/refresh", methods=["POST"])
@jwt_required
def refresh_logout():
    jti = get_raw_jwt()["jti"]
    try:
        invalid_token = InvalidToken(jti=jti)
        invalid_token.save()
        return jsonify({"success": True})
    except Exception as e:
        print(e)
        return {"error": e}

class Tweet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uid = db.Column(db.Integer, db.ForeignKey("user.id"))
    user = db.relationship('User', foreign_keys=uid)
    title = db.Column(db.String(256))
    content = db.Column(db.String(2048))

    def get():
        tweets = Tweet.query.all()
        return [{"id": i.id, "title": i.title, "content": i.content, "user": User.getUser(i.uid)} for i in tweets]

    def getFromUser(uid):
        tweets = Tweet.query.all()
        return [{"id": item.id, "userid": item.user_id, "title": item.title, "content": item.content} for item in filter(lambda i: i.user_id == uid, tweets)]

    def add(title, content, uid):
        if (title and content and uid):
            try:
                users = list(filter(lambda i: i.id == uid, User.query.all()))
                if not users:
                    print("No users were found.")
                    return False
                user = users[0]
                twt = Tweet(title=title, content=content, user=user)
                db.session.add(twt)
                db.session.commit()
                return True
            except IntegrityError as e:
                print(e)
                return False
        else:
            return False
            
    def delete(tid):
        try:
            tweet = Tweet.query.get(tid)
            db.session.delete(tweet)
            db.session.commit()
            return True
        except Exception as e:
            print(e)
            return False

class User(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(24), unique=True)
    email = db.Column(db.String(64), unique=True)
    pwd = db.Column(db.String(64))

    def __init__(self, username, email, pwd):
        self.username = username
        self.email = email
        self.pwd = pwd

    def getUser(uid):
        users = User.query.all()
        user = list(filter(lambda x: x.id == uid, users))[0]
        return {"id": user.id, "username": user.username, "email": user.email, "password": user.pwd}

    def getUsers():
        users = User.query.all()
        return [{"id": i.id, "username": i.username, "email": i.email, "password": i.pwd} for i in users]

    def addUser(username, email, pwd):
        try:
            user = User(username, email, pwd)
            db.session.add(user)
            db.session.commit()
            return True
        except IntegrityError as e:
            print("User already exists:")
            return False
    
        def removeUser(uid):
            try:
                user = User.query.get(uid)
                db.session.delete(user)
                db.session.commit()
                return True
            except Exception as e:
                print(e)
                return False

@app.route("/api/tweets")
def get_tweets():
    return jsonify(Tweet.get())

@app.route("/api/deletetweet", methods=["DELETE"])
@jwt_required
def delete_tweet():
    try:
        tid = request.json["tid"]
        return jsonify(Tweet.delete(tid))
    except Exception as e:
        return jsonify({"error": e})

@app.route("/api/addtweet", methods=["POST"])
@jwt_required
def add_tweet():
    try:
        title = request.json["title"]
        content = request.json["content"]
        uid = get_jwt_identity()
        return jsonify({"success": Tweet.add(title, content, uid)})
    except Exception as e:
        return jsonify({"error": e})

@app.route("/api/login", methods=["POST"])
def login():
    try:
        email = request.json["email"]
        password = request.json["pwd"]
        if (email and password):
            user = list(filter(lambda x: x["email"] == email and x["password"] == password, User.getUsers()))
            if len(user) == 1:
                token = create_access_token(identity=user[0]["id"])
                return jsonify({"token": token})
            else:
                return jsonify({"error": "Invalid credentials"})
        else:
            return jsonify({"error": "Invalid form"})
    except Exception as e:
        print(e)
        return jsonify({"error": "Invalid form"})

@app.route("/api/register", methods=["POST"])
def register():
    try:
        email = request.json["email"]
        email = email.lower()
        password = request.json["pwd"]
        username = request.json["username"]
        users = User.getUsers()

        if not re.match(r"[\w\._]{5,}@\w{3,}.\w{2,4}", email):
            return jsonify({"error": "Invalid form"})
        
        User.addUser(username, email, password)
        
        return jsonify({"success": True})
    
    except Exception as e:
        return jsonify({"error": e})

@app.route("/api/users", methods=["GET", "POST", "DELETE"])        
def users():
    method = request.method
    if (method.lower() == "get"):
        users = User.query.all()
        return jsonify([{"id": i.id, "username": i.username, "email": i.email, "password": i.pwd} for i in users])
    elif (method.lower() == "post"):
        try:
            username = request.json["username"]
            email = request.json["email"]
            pwd = request.json["pwd"]
            if (username and pwd and email):
                try:
                    user = User(username, email, pwd)
                    db.session.add(user)
                    db.session.commit()
                    return jsonify({"success": True})
                except Exception as e:
                    return ({"error": e})
            else:
                return jsonify({"error": "Invalid form"})
        except:
            return jsonify({"error": "Invalid form"})
    elif (method.lower() == "delete"):
        try:
            uid = request.json["id"]
            if (uid):
                try:
                    user = User.query.get(uid)
                    db.session.delete(user)
                    db.session.commit()
                    return jsonify({"success": True})
                except Exception as e:
                    return jsonify({"error": e})
            else:
                return jsonify({"error": "Invalid form"})
            
        except Exception as e:
            return jsonify({"error": e})

if __name__ == "__main__":
    db.create_all()
    app.run()
