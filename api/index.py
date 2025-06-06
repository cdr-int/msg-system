from flask import Flask, request, render_template, redirect, url_for, flash, session, Response
from pymongo import MongoClient
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
import os
import time
import pytz
from datetime import datetime, timedelta
import json
from bson import ObjectId
import hashlib
from markupsafe import escape
import re
from markupsafe import escape, Markup
import markdown2
from pygments import highlight
from pygments.lexers import get_lexer_by_name, TextLexer
from pygments.formatters import HtmlFormatter

# Initialize Flask app
app = Flask(__name__)

# Use a fixed secret key (replace with environment variable in production)
app.secret_key = os.environ.get('SECRET_KEY', 'supersecretkey123')

# Make sessions permanent and set lifetime
app.permanent_session_lifetime = timedelta(days=7)


@app.before_request
def make_session_permanent():
    session.permanent = True


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


# Create a scheduler to clear the database at midnight UK time every day
scheduler = BackgroundScheduler(daemon=True)
scheduler.add_job(clear_messages,
                  CronTrigger(hour=0, minute=0, second=0,
                              timezone=UK_TIMEZONE),
                  id='clear_db_at_midnight')
scheduler.start()


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


# Cache the bad words globally
bad_words = set()


def load_restricted_words(file_path="api/static/bad_words.txt"):
    global bad_words
    # Only load the words if they haven't been loaded already
    if not bad_words:
        with open(file_path, "r") as file:
            # Read all lines, strip newlines, and convert to lowercase
            bad_words = {line.strip().lower() for line in file.readlines()}
    return bad_words


def format_message_content(content):
    content = escape(content)

    def highlight_code_block(match):
        lang = match.group(1)
        code = match.group(2)
        # Unescape code so Pygments highlights it correctly
        code = code.replace('&lt;', '<').replace('&gt;', '>').replace('&amp;', '&')
        try:
            lexer = get_lexer_by_name(lang, stripall=True) if lang else TextLexer()
        except Exception:
            lexer = TextLexer()
        formatter = HtmlFormatter(nowrap=True)
        highlighted_code = highlight(code, lexer, formatter)
        return f'<pre><code class="codehilite">{highlighted_code}</code></pre>'

    pattern = re.compile(r'```(?:([a-zA-Z0-9_+-]+)?\n)?(.*?)```', re.DOTALL)
    content, n = pattern.subn(highlight_code_block, content)
    # Debug print number of code blocks replaced
    print(f"Code blocks replaced: {n}")

    def inline_code_replacer(match):
        code = match.group(1)
        code = code.replace('&lt;', '<').replace('&gt;', '>').replace('&amp;', '&')
        return f'<code>{code}</code>'

    content = re.sub(r'`([^`\n]+)`', inline_code_replacer, content)

    content = re.sub(r'__(.*?)__', r'<u>\1</u>', content)
    content = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', content)
    content = re.sub(r'\*(.*?)\*', r'<em>\1</em>', content)

    parts = re.split(r'(<pre><code class="codehilite">.*?</code></pre>)', content, flags=re.DOTALL)
    for i in range(len(parts)):
        if not parts[i].startswith('<pre><code'):
            parts[i] = parts[i].replace('\n', '<br>')
    content = ''.join(parts).strip()

    return content




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
            "theme": 0,  # 0 for light mode, 1 for dark mode
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
            session["theme"] = user.get("theme", 0)
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
        flash("You do not have permission to access the admin dashboard.",
              "error")
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


@app.route("/admin/update_permission/<user_id>", methods=["POST"])
def update_permission(user_id):
    # Check if user is logged in and has admin permission
    if "user_id" not in session:
        flash("You must be logged in to perform this action.", "error")
        return redirect(url_for("login"))

    if session.get("permission_level", 0) != 1:
        flash("You do not have permission to perform this action.", "error")
        return redirect(url_for("index"))

    # Check if user is trying to change their own permission level
    if user_id == session["user_id"]:
        flash("You cannot change your own permission level.", "error")
        return redirect(url_for("admin_dashboard"))

    # Get the new permission level from the form
    new_permission_level = int(request.form["permission_level"])

    # Update the user's permission level
    result = users_collection.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {
            "permission_level": new_permission_level
        }})

    if result.modified_count > 0:
        # Get the username for the flash message
        user = users_collection.find_one({"_id": ObjectId(user_id)})
        username = user["username"] if user else "User"
        flash(f"Permission level for {username} updated successfully.",
              "success")
    else:
        flash("Failed to update permission level.", "error")

    return redirect(url_for("admin_dashboard"))


@app.route("/admin/reset_password/<user_id>", methods=["POST"])
def reset_password(user_id):
    # Check if user is logged in and has admin permission
    if "user_id" not in session:
        flash("You must be logged in to perform this action.", "error")
        return redirect(url_for("login"))

    if session.get("permission_level", 0) != 1:
        flash("You do not have permission to perform this action.", "error")
        return redirect(url_for("index"))

    # Reset the user's password to 'password123'
    new_password = "password123"
    hashed_password = hash_password(new_password)

    result = users_collection.update_one(
        {"_id": ObjectId(user_id)}, {"$set": {
            "password": hashed_password
        }})

    if result.modified_count > 0:
        # Get the username for the flash message
        user = users_collection.find_one({"_id": ObjectId(user_id)})
        username = user["username"] if user else "User"
        flash(f"Password for {username} has been reset to 'password123'.",
              "success")
    else:
        flash("Failed to reset password.", "error")

    return redirect(url_for("admin_dashboard"))


@app.route("/settings/reset_password", methods=["POST"])
def settings_reset_password():
    # Check if user is logged in
    if "user_id" not in session:
        flash("You must be logged in to perform this action.", "error")
        return redirect(url_for("login"))

    current_password = request.form["current_password"]
    new_password = request.form["new_password"]
    confirm_password = request.form["confirm_password"]

    # Verify current password
    user = users_collection.find_one({"_id": ObjectId(session["user_id"])})
    if not user or user["password"] != hash_password(current_password):
        flash("Current password is incorrect.", "error")
        return redirect(url_for("index"))

    # Check if new passwords match
    if new_password != confirm_password:
        flash("New passwords do not match.", "error")
        return redirect(url_for("index"))

    # Update password
    hashed_new_password = hash_password(new_password)
    result = users_collection.update_one(
        {"_id": ObjectId(session["user_id"])},
        {"$set": {
            "password": hashed_new_password
        }})

    if result.modified_count > 0:
        flash("Password updated successfully.", "success")
    else:
        flash("Failed to update password.", "error")

    return redirect(url_for("index"))


@app.route("/settings/toggle_theme", methods=["POST"])
def toggle_theme():
    # Check if user is logged in
    if "user_id" not in session:
        flash("You must be logged in to perform this action.", "error")
        return redirect(url_for("login"))

    try:
        # Get current theme and toggle it
        current_theme = session.get("theme", 0)
        new_theme = 1 if current_theme == 0 else 0

        # Update theme in database
        result = users_collection.update_one(
            {"_id": ObjectId(session["user_id"])},
            {"$set": {
                "theme": new_theme
            }})

        if result.matched_count > 0:  # Check if user was found
            if result.modified_count > 0:
                session["theme"] = new_theme
                flash("Theme updated successfully.", "success")
            else:
                session["theme"] = new_theme  # Update session anyway
                flash("Theme updated successfully.", "success")
        else:
            flash("User  not found in database.", "error")

    except Exception as e:
        print(f"Error updating theme: {e}")
        flash(f"Failed to update theme: {str(e)}", "error")

    # Store the current page in the session
    session['current_page'] = request.referrer or url_for('index')

    return redirect(session['current_page'])



# Updated route - store as plain string, not Markup object
@app.route("/", methods=["GET", "POST"])
def index():
    load_restricted_words()

    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        content = request.form["content"]
        content_lower = content.lower()

        if any(bad_word in content_lower for bad_word in bad_words):
            flash("Your message contains restricted words and cannot be sent.",
                  "error")
            return redirect(url_for("index"))

        current_time = time.time()
        user_id = session["user_id"]

        if user_id in user_last_message_time and current_time - user_last_message_time[
                user_id] < 5:
            flash("You need to wait 5 seconds before sending another message.",
                  "error")
            return redirect(url_for("index"))

        if content:
            # Format the message content
            formatted_content = format_message_content(content)

            # Create the message with username - store as plain string
            message_with_username = f"<strong class='username-highlight'>{escape(session['username'])}:</strong> {formatted_content}"

            # Insert as plain string, not Markup object
            messages_collection.insert_one({
                "content": message_with_username,  # Store as plain string
                "createdAt": current_time,
                "user_id": user_id
            })

            user_last_message_time[user_id] = current_time
            flash("Message sent successfully!", "success")

        return redirect(url_for("index"))

    # Retrieve all messages from the database
    messages = messages_collection.find().sort("createdAt", -1)
    return render_template("index.html", messages=messages)


@app.route("/admin/delete_user/<user_id>", methods=["POST"])
def delete_user(user_id):
    # Only admin can delete users
    if "user_id" not in session:
        flash("You must be logged in to perform this action.", "error")
        return redirect(url_for("login"))

    if session.get("permission_level", 0) != 1:
        flash("You do not have permission to perform this action.", "error")
        return redirect(url_for("index"))

    if user_id == session["user_id"]:
        flash("You cannot delete your own account.", "error")
        return redirect(url_for("admin_dashboard"))

    # Delete user
    result = users_collection.delete_one({"_id": ObjectId(user_id)})
    if result.deleted_count > 0:
        flash("User deleted successfully.", "success")
    else:
        flash("User not found.", "error")

    return redirect(url_for("admin_dashboard"))


@app.route("/stream")
def stream():

    def event_stream():
        # Start from current time to avoid sending old messages
        last_timestamp = time.time()

        # Send a heartbeat first to establish connection
        yield "data: {\"type\": \"heartbeat\"}\n\n"

        while True:
            try:
                # Query for messages newer than last_timestamp
                new_messages = list(
                    messages_collection.find({
                        "createdAt": {
                            "$gt": last_timestamp
                        }
                    }).sort("createdAt", 1))

                if new_messages:
                    # Update last_timestamp to the newest message's timestamp
                    last_timestamp = new_messages[-1]["createdAt"]

                    # Send each message individually
                    for message in new_messages:
                        data = json.dumps({
                            "type": "message",
                            "content": message["content"],
                            "createdAt": message["createdAt"],
                            "id": str(message["_id"])
                        })
                        yield f"data: {data}\n\n"
                else:
                    # Send heartbeat to keep connection alive
                    yield "data: {\"type\": \"heartbeat\"}\n\n"

                time.sleep(2)  # Check for new messages every 2 seconds

            except Exception as e:
                print(f"SSE Stream error: {e}")
                # Send error message and break
                yield f"data: {{\"type\": \"error\", \"message\": \"Connection lost\"}}\n\n"
                break

    response = Response(event_stream(), mimetype="text/event-stream")
    response.headers['Cache-Control'] = 'no-cache'
    response.headers['Connection'] = 'keep-alive'
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['X-Accel-Buffering'] = 'no'  # Disable nginx buffering
    return response


if __name__ == "__main__":
    app.run(debug=True, threaded=True)
