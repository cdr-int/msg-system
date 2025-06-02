from flask import Flask, request, render_template, redirect, url_for, flash, session, Response
from pymongo import MongoClient
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
import os
import time
import pytz
from datetime import datetime
import json
from bson import ObjectId
import hashlib

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.urandom(
    24)  # Required for flash messages and session handling

# MongoDB URI (modified to include the database name directly)
MONGO_URI = "mongodb+srv://c828522:jamie@cluster0.sfwht.mongodb.net/anonymous_messaging?retryWrites=true&w=majority&appName=Cluster0"

# Set up MongoDB client
client = MongoClient(MONGO_URI)

# Explicitly define the database
db = client['anonymous_messaging']  # Replace with your database name
messages_collection = db.messages
users_collection = db.users

# Store user-specific message cooldowns
user_last_message_time = {}

# Timezone setup
UK_TIMEZONE = pytz.timezone('Europe/London')


# Schedule background task for clearing the database
def clear_messages():
    # Clear all messages from the database
    messages_collection.delete_many({})
    print(f"Database cleared at {datetime.now(UK_TIMEZONE)}")


# Create a scheduler to clear the database at 11:15 AM UK time every day
scheduler = BackgroundScheduler(daemon=True)
scheduler.add_job(
    clear_messages,
    CronTrigger(
        hour=0,  # Set to 0 for midnight (12:00 AM)
        minute=0,  # Set to 0 for the start of the hour
        second=0,  # Set to 0 for the start of the minute
        timezone=UK_TIMEZONE),  # Make sure to use the UK timezone
    id='clear_db_at_midnight')
scheduler.start()


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        
        # Check if username already exists
        if users_collection.find_one({"username": username}):
            flash("Username already exists!", "error")
            return redirect(url_for("signup"))
        
        # Create new user
        hashed_password = hash_password(password)
        users_collection.insert_one({
            "username": username,
            "password": hashed_password,
            "permission_level": 0,
            "createdAt": time.time()
        })
        
        flash("Account created successfully! Please log in.", "success")
        return redirect(url_for("login"))
    
    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        
        # Find user in database
        user = users_collection.find_one({"username": username})
        if user and user["password"] == hash_password(password):
            session["user_id"] = str(user["_id"])
            session["username"] = user["username"]
            session["permission_level"] = user.get("permission_level", 0)
            flash(f"Welcome back, {username}!", "success")
            return redirect(url_for("index"))
        else:
            flash("Invalid username or password!", "error")
    
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))

@app.route("/admin")
def admin_dashboard():
    # Check if user is logged in
    if "user_id" not in session:
        flash("You must be logged in to access this page.", "error")
        return redirect(url_for("login"))
    
    # Check if user has admin permission
    if session.get("permission_level", 0) != 1:
        flash("You do not have permission to access the admin dashboard.", "error")
        return redirect(url_for("index"))
    
    # Get all users and messages for admin view
    users = users_collection.find().sort("createdAt", -1)
    messages = messages_collection.find().sort("createdAt", -1)
    
    return render_template("admin.html", users=users, messages=messages)

@app.route("/admin/delete_message/<message_id>", methods=["POST"])
def delete_message(message_id):
    # Check if user is logged in and has admin permission
    if "user_id" not in session:
        flash("You must be logged in to perform this action.", "error")
        return redirect(url_for("login"))
    
    if session.get("permission_level", 0) != 1:
        flash("You do not have permission to perform this action.", "error")
        return redirect(url_for("index"))
    
    # Delete the message
    result = messages_collection.delete_one({"_id": ObjectId(message_id)})
    if result.deleted_count > 0:
        flash("Message deleted successfully.", "success")
    else:
        flash("Message not found.", "error")
    
    return redirect(url_for("admin_dashboard"))

# Route to display messages and send new ones
@app.route("/", methods=["GET", "POST"])
def index():
    # Check if user is logged in
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        # Check the time since the last message for this user
        current_time = time.time()
        user_id = session["user_id"]
        
        if user_id in user_last_message_time and current_time - user_last_message_time[user_id] < 5:
            # If the cooldown period hasn't passed, show an error message
            flash(
                "You need to wait 5 seconds before sending another message.",
                "error")
            return redirect(url_for("index"))

        # Get the message content from the form
        content = request.form["content"]
        if content:
            # Prepend the username to the message
            message_with_username = f"<strong>{session['username']}</strong>: {content}"

            # Insert the new message into MongoDB
            messages_collection.insert_one({
                "content": message_with_username,
                "createdAt": current_time,
                "user_id": user_id
            })
            # Update the last message time for this user
            user_last_message_time[user_id] = current_time
            flash("Message sent successfully!", "success")
        return redirect(url_for("index"))

    # Retrieve all messages from the database
    messages = messages_collection.find().sort("createdAt", -1)
    return render_template("index.html", messages=messages)


# Custom JSON encoder to handle ObjectId serialization
class MongoJSONEncoder(json.JSONEncoder):

    def default(self, obj):
        if isinstance(obj, ObjectId):
            return str(obj)  # Convert ObjectId to string
        return super().default(obj)


# SSE route for streaming messages in real-time
@app.route('/stream')
def stream():
    # Check if user is logged in
    if "user_id" not in session:
        # Return a proper SSE response instead of 401
        def error_stream():
            yield "event: error\ndata: unauthorized\n\n"
        return Response(error_stream(), content_type='text/event-stream')

    def generate():
        last_checked_time = time.time()

        while True:
            try:
                # Check if user is still logged in
                if "user_id" not in session:
                    yield "event: error\ndata: session_expired\n\n"
                    break
                    
                # Query the database for any new messages since the last check
                new_messages = messages_collection.find({
                    "createdAt": {
                        "$gt": last_checked_time
                    }
                }).sort("createdAt", 1)
                for message in new_messages:
                    yield f"data: {json.dumps(message, cls=MongoJSONEncoder)}\n\n"
                    last_checked_time = message[
                        "createdAt"]  # Update the last checked time

                time.sleep(1)  # Wait for 1 second before checking again
            except Exception as e:
                yield f"event: error\ndata: {str(e)}\n\n"
                break

    return Response(generate(), content_type='text/event-stream')


# Run the Flask app
if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)