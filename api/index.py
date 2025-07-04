from flask import Flask, request, render_template, redirect, url_for, flash, session, Response, make_response
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
from markupsafe import escape, Markup
import re
import markdown
import html
from markdown.extensions import Extension
from markdown.preprocessors import Preprocessor

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
MONGO_URI = "mongodb+srv://c828522:jamie@cluster0.sfwht.mongodb.net/pulse_chat_db?retryWrites=true&w=majority&appName=Cluster0"

# Set up MongoDB client
client = MongoClient(MONGO_URI)

# Explicitly define the database
db = client['pulse_chat_db']  # Replace with your database name
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


def html_to_text(html_content):
    # First, decode HTML entities
    text = html.unescape(html_content)
    # Remove HTML tags using regex
    clean_text = re.sub(r'<[^>]+>', '', text)
    return clean_text


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


class UnderlineExtension(Extension):
    """Custom extension to handle __ as underline instead of bold"""

    def extendMarkdown(self, md):
        # Add the underline preprocessor with high priority
        # This runs before the standard bold/italic processing
        md.preprocessors.register(UnderlinePreprocessor(md), 'underline', 30)


class UnderlinePreprocessor(Preprocessor):
    """Preprocessor to convert __text__ to <u>text</u> before standard markdown processing"""

    def run(self, lines):
        # Join all lines to handle multi-line underlined text
        text = '\n'.join(lines)

        # Replace __text__ with <u>text</u> using non-greedy matching
        # This pattern handles nested formatting and prevents conflicts
        underline_pattern = r'__([^_\n]*(?:_(?!_)[^_\n]*)*)__'
        text = re.sub(underline_pattern, r'<u>\1</u>', text)

        # Split back into lines
        return text.split('\n')


def format_message_content(content):
    """
    Enhanced markdown processing with custom underline support using __ syntax
    """
    # Initialize markdown with comprehensive extensions including our custom underline extension
    md = markdown.Markdown(
        extensions=[
            UnderlineExtension(
            ),  # Our custom underline extension (must be first)
            'codehilite',  # Syntax highlighting for code blocks
            'fenced_code',  # ```code``` blocks
            'tables',  # Table support
            'toc',  # Table of contents
            'sane_lists',  # Better list handling
            'attr_list',  # Attribute lists for styling
            'def_list',  # Definition lists
            'abbr',  # Abbreviations
            'footnotes',  # Footnote support
            'admonition',  # Admonition blocks (!!! note)
            'meta',  # Metadata support
            'wikilinks',  # Wiki-style links
            'smarty'  # Smart quotes and typography
        ],
        extension_configs={
            'codehilite': {
                'css_class': 'codehilite',
                'use_pygments': True,
                'noclasses': False,
                'linenos': False
            },
            'toc': {
                'permalink': True,
                'permalink_class': 'toc-permalink',
                'permalink_title': 'Permanent link'
            }
        })

    # Convert markdown to HTML
    html_content = md.convert(content)

    # Return as Markup object to prevent double escaping
    return Markup(html_content)


@app.route("/privacy", methods=["GET", "POST"])
def privacy():
    return render_template("privacy.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        # Check cooldown cookie first
        last_signup_time = request.cookies.get("last_signup_time")
        current_time = time.time()

        if last_signup_time:
            try:
                last_signup_time = float(last_signup_time)
                if current_time - last_signup_time < 10 * 60:  # 10 minutes cooldown
                    flash(
                        "You must wait 10 minutes between account creations on this device.",
                        "error")
                    return redirect(url_for("signup"))
            except ValueError:
                # Invalid cookie value, ignore and continue
                pass

        username = request.form["username"]
        password = request.form["password"]

        # Username validation
        username_errors = []
        if not (4 <= len(username) <= 15):
            username_errors.append(
                "Username must be between 4 and 15 characters.")
        if not re.match(r'^[A-Za-z0-9]+$', username):
            username_errors.append(
                "Username can only contain letters and numbers, no spaces or special characters."
            )

        if username_errors:
            for error in username_errors:
                flash(error, "error")
            return redirect(url_for("signup"))

        # Check if username already exists
        if users_collection.find_one({"username": username}):
            flash("Username already exists!", "error")
            return redirect(url_for("signup"))

        # Password validation
        password_errors = []
        if len(password) < 6:
            password_errors.append(
                "Password must be at least 6 characters long.")
        if not re.search(r"[A-Z]", password):
            password_errors.append(
                "Password must contain at least one uppercase letter.")
        if not re.search(r"[a-z]", password):
            password_errors.append(
                "Password must contain at least one lowercase letter.")
        if not re.search(r"\d", password):
            password_errors.append("Password must contain at least one digit.")

        if password_errors:
            for error in password_errors:
                flash(error, "error")
            return redirect(url_for("signup"))

        # Create new user
        hashed_password = hash_password(password)
        users_collection.insert_one({
            "username": username,
            "password": hashed_password,
            "permission_level": 0,
            "theme": 0,
            "createdAt": current_time
        })

        flash("Account created successfully! Please log in.", "success")

        # Set cookie with current time, expires in 10 minutes
        response = make_response(redirect(url_for("login")))
        response.set_cookie("last_signup_time",
                            str(current_time),
                            max_age=10 * 60,
                            httponly=True)
        return response

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

    # Check if user has admin permission (level 1 or higher)
    if session.get("permission_level", 0) < 1:
        flash("You do not have permission to access the admin dashboard.",
              "error")
        return redirect(url_for("index"))

    # Get all users and messages for admin view
    users = list(users_collection.find().sort("createdAt", -1))
    messages_cursor = messages_collection.find().sort("createdAt", -1)

    # For each message, escape the formatted_content to show HTML tags as text
    messages = []
    for msg in messages_cursor:
        # Create a copy to avoid modifying original
        msg_copy = dict(msg)
        if 'formatted_content' in msg_copy:
            # Escape HTML so tags are visible as text
            msg_copy['formatted_content'] = escape(
                msg_copy['formatted_content'])
        messages.append(msg_copy)

    return render_template("admin.html", users=users, messages=messages)


@app.route("/admin/delete_message/<message_id>", methods=["POST"])
def delete_message(message_id):
    # Check if user is logged in and has admin access (level 1 or higher)
    if "user_id" not in session:
        flash("You must be logged in to perform this action.", "error")
        return redirect(url_for("login"))

    if session.get("permission_level", 0) < 1:
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
    if "user_id" not in session:
        flash("You must be logged in to perform this action.", "error")
        return redirect(url_for("login"))

    current_level = session.get("permission_level", 0)

    # Minimum permission level to update permissions is Admin (2)
    if current_level < 2:
        flash("You do not have permission to perform this action.", "error")
        return redirect(url_for("admin_dashboard"))

    if user_id == session["user_id"]:
        flash("You cannot change your own permission level.", "error")
        return redirect(url_for("admin_dashboard"))

    try:
        new_permission_level = int(request.form["permission_level"])
    except (ValueError, KeyError):
        flash("Invalid permission level.", "error")
        return redirect(url_for("admin_dashboard"))

    target_user = users_collection.find_one({"_id": ObjectId(user_id)})
    if not target_user:
        flash("User not found.", "error")
        return redirect(url_for("admin_dashboard"))

    target_level = target_user.get("permission_level", 0)

    if current_level == 3:
        pass  # Owner can do anything

    elif current_level == 2:
        if new_permission_level > 2:
            flash("Admins cannot assign Owner (level 3) permissions.", "error")
            return redirect(url_for("admin_dashboard"))

        if target_level >= current_level:
            flash(
                "You cannot change permissions of users with equal or higher level.",
                "error")
            return redirect(url_for("admin_dashboard"))

        if new_permission_level > current_level:
            flash("You cannot assign a permission level higher than your own.",
                  "error")
            return redirect(url_for("admin_dashboard"))

    else:
        flash("You do not have permission to perform this action.", "error")
        return redirect(url_for("admin_dashboard"))

    # Update the user's permission level
    result = users_collection.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {
            "permission_level": new_permission_level
        }})

    if result.modified_count > 0:
        flash(
            f"Permission level for {target_user['username']} updated successfully.",
            "success")
    else:
        flash("Failed to update permission level.", "error")

    return redirect(url_for("admin_dashboard"))


@app.route("/admin/reset_password/<user_id>", methods=["POST"])
def reset_password(user_id):
    # Check if user is logged in and has admin access (level 1 or higher)
    if "user_id" not in session:
        flash("You must be logged in to perform this action.", "error")
        return redirect(url_for("login"))

    if session.get("permission_level", 0) < 1:
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


@app.route("/", methods=["GET", "POST"])
def index():
    load_restricted_words()

    if "user_id" not in session:
        return redirect(url_for("login"))

    user_id = session["user_id"]

    # Check if user still exists in the database
    user_exists = users_collection.find_one({"_id": ObjectId(user_id)})
    if not user_exists:
        session.clear()
        flash("Your account no longer exists. You have been logged out.",
              "error")
        return redirect(url_for("login"))

    if request.method == "POST":
        content = request.form["content"]
        content_lower = content.lower()

        # Check message length limit
        if len(content) > 2000:  # Increased limit for markdown content
            flash("Message cannot be longer than 2000 characters.", "error")
            return redirect(url_for("index"))

        if any(bad_word in content_lower for bad_word in bad_words):
            flash("Your message contains restricted words and cannot be sent.",
                  "error")
            return redirect(url_for("index"))

        current_time = time.time()

        if user_id in user_last_message_time and current_time - user_last_message_time[
                user_id] < 5:
            flash("You need to wait 5 seconds before sending another message.",
                  "error")
            return redirect(url_for("index"))

        if content:
            # Process markdown content
            formatted_content = format_message_content(content)

            # Check if user has admin permission and add [admin] prefix
            username_display = session['username']
            if session.get("permission_level", 0) == 1:
                username_display = f"<span class='mod-tag'>[mod]</span> {username_display}"
            elif session.get("permission_level", 0) == 2:
                username_display = f"<span class='admin-tag'>[admin]</span> {username_display}"
            elif session.get("permission_level", 0) == 3:
                username_display = f"<span class='owner-tag'>[owner]</span> {username_display}"

            # Create message with username and formatted content
            message_with_username = f"<strong class='username-highlight'>{escape(username_display)}:</strong><div class='message-content'>{formatted_content}</div>"

            # Determine permission tag
            permission_level = session.get("permission_level", 0)
            if permission_level == 1:
                permission_tag = "[mod]"
            elif permission_level == 2:
                permission_tag = "[admin]"
            elif permission_level == 3:
                permission_tag = "[owner]"
            else:
                permission_tag = ""

            messages_collection.insert_one({
                "content":
                content,  # Store original markdown content
                "formatted_content":
                str(formatted_content),  # Store rendered HTML
                "createdAt":
                current_time,
                "user_id":
                user_id,
                "permission_tag":
                permission_tag,
                "username":
                session['username']
            })

            user_last_message_time[user_id] = current_time
            flash("Message sent successfully!", "success")

        return redirect(url_for("index"))

    messages = messages_collection.find().sort("createdAt", -1)
    return render_template("index.html", messages=messages)


@app.route("/admin/delete_user/<user_id>", methods=["POST"])
def delete_user(user_id):
    # Only admin (level 2) or higher can delete users
    if "user_id" not in session:
        flash("You must be logged in to perform this action.", "error")
        return redirect(url_for("login"))

    if session.get("permission_level", 0) < 2:
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
    print("Stream endpoint accessed")  # Debug log

    if "user_id" not in session:
        print("User not authenticated for stream")  # Debug log
        return Response(
            json.dumps({
                "type": "error",
                "message": "Not authenticated"
            }),
            mimetype="application/json",
            status=401,
        )

    user_id = session["user_id"]
    print(f"Stream started for user: {user_id}")  # Debug log

    def event_stream():
        try:
            # Use timestamp instead of datetime for consistency with your message storage
            last_timestamp = time.time()
            print(f"Stream initialized with timestamp: {last_timestamp}")  # Debug log

            # Send initial heartbeat
            yield "data: {\"type\": \"heartbeat\"}\n\n"

            while True:
                try:
                    # Check if user still exists
                    user_exists = users_collection.find_one({"_id": ObjectId(user_id)})
                    if not user_exists:
                        print(f"User {user_id} no longer exists")  # Debug log
                        yield f"data: {{\"type\": \"error\", \"message\": \"User no longer exists. Connection closing.\"}}\n\n"
                        break

                    # Query for new messages using timestamp
                    new_messages = list(
                        messages_collection.find({
                            "createdAt": {
                                "$gt": last_timestamp
                            }
                        }).sort("createdAt", 1)
                    )

                    if new_messages:
                        print(f"Found {len(new_messages)} new messages")  # Debug log
                        # Update last_timestamp to the latest message timestamp
                        last_timestamp = new_messages[-1]["createdAt"]

                        for message in new_messages:
                            try:
                                # Get the formatted content
                                content = message.get("formatted_content")
                                if not content:
                                    content = str(format_message_content(message["content"]))

                                # Get username and permission info
                                username_display = message.get("username", "Unknown")

                                # Get user permission level for proper display
                                user_doc = users_collection.find_one({"_id": ObjectId(message["user_id"])})
                                permission_level = 0
                                if user_doc:
                                    permission_level = user_doc.get("permission_level", 0)

                                # Add permission tags to username
                                if permission_level == 1:
                                    username_display = f"<span class='mod-tag'>[mod]</span> {escape(username_display)}"
                                elif permission_level == 2:
                                    username_display = f"<span class='admin-tag'>[admin]</span> {escape(username_display)}"
                                elif permission_level == 3:
                                    username_display = f"<span class='owner-tag'>[owner]</span> {escape(username_display)}"
                                else:
                                    username_display = escape(username_display)

                                # Create the full message HTML
                                message_html = f"<strong class='username-highlight'>{username_display}:</strong><div class='message-content'>{content}</div>"

                                data = {
                                    "type": "message",
                                    "content": message["content"],
                                    "formatted_content": message_html,
                                    "createdAt": message["createdAt"],
                                    "id": str(message["_id"]),
                                    "permission_tag": message.get("permission_tag", ""),
                                    "username": message.get("username", "Unknown")
                                }

                                data_json = json.dumps(data)
                                print(f"Sending message: {data_json[:100]}...")  # Debug log (truncated)
                                yield f"data: {data_json}\n\n"

                            except Exception as msg_error:
                                print(f"Error processing message: {msg_error}")  # Debug log
                                continue
                    else:
                        # Send heartbeat to keep connection alive
                        yield "data: {\"type\": \"heartbeat\"}\n\n"

                    # Flush the output to ensure it's sent immediately
                    time.sleep(1)

                except Exception as loop_error:
                    print(f"Error in stream loop: {loop_error}")  # Debug log
                    yield f"data: {{\"type\": \"error\", \"message\": \"Stream error: {str(loop_error)}\"}}\n\n"
                    break

        except Exception as stream_error:
            print(f"Fatal stream error: {stream_error}")  # Debug log
            yield f"data: {{\"type\": \"error\", \"message\": \"Fatal stream error: {str(stream_error)}\"}}\n\n"

    try:
        response = Response(event_stream(), mimetype="text/event-stream")
        response.headers['Cache-Control'] = 'no-cache'
        response.headers['Connection'] = 'keep-alive'
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['X-Accel-Buffering'] = 'no'
        response.headers['Content-Type'] = 'text/event-stream'
        response.headers['Transfer-Encoding'] = 'chunked'

        print("Stream response created successfully")  # Debug log
        return response

    except Exception as response_error:
        print(f"Error creating stream response: {response_error}")  # Debug log
        return Response(
            json.dumps({
                "type": "error", 
                "message": f"Failed to create stream: {str(response_error)}"
            }),
            mimetype="application/json",
            status=500
        )




if __name__ == "__main__":
    app.run(debug=True, threaded=True)
