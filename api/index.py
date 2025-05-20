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

# Store the timestamp of the last message sent (initially, no messages sent)
last_message_time = 0

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


# Route to display messages and send new ones
@app.route("/", methods=["GET", "POST"])
def index():
    global last_message_time  # Use the global last_message_time variable

    # Check if the username is set in the session
    if "username" not in session:
        if request.method == "POST" and "username" in request.form:
            # Set the username in the session
            session["username"] = request.form["username"]
            flash(f"Welcome, {session['username']}!", "success")
            return redirect(url_for("index"))

    if request.method == "POST":
        # Check the time since the last message
        current_time = time.time()
        if current_time - last_message_time < 10:
            # If the cooldown period hasn't passed, show an error message
            flash(
                "You need to wait 10 seconds before sending another message.",
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
                "createdAt": current_time
            })
            # Update the last message time
            last_message_time = current_time
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

    def generate():
        last_checked_time = time.time()

        while True:
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

    return Response(generate(), content_type='text/event-stream')


# Run the Flask app
if __name__ == "__main__":
    app.run(debug=True)
