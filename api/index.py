    from flask import Flask, render_template, request, redirect, url_for, session, flash, Response
    from werkzeug.security import generate_password_hash, check_password_hash
    from pymongo import MongoClient
    from bson import ObjectId
    import json
    import time
    import threading

    app = Flask(__name__)
    app.secret_key = 'your-secret-key'  # Replace with your own secret key

    # MongoDB setup (replace your URI as needed)
    client = MongoClient("mongodb+srv://<username>:<password>@cluster0.mongodb.net/mydb?retryWrites=true&w=majority")
    db = client['mydb']

    # Collections
    users_col = db.users
    messages_col = db.messages

    # Helper to serialize messages for JSON output in SSE
    def serialize_message(msg):
        return {
            "_id": str(msg["_id"]),
            "content": msg.get("content", ""),
            "createdAt": msg.get("createdAt"),
            "user_id": msg.get("user_id")
        }

    # Helper to serialize users for templates
    def serialize_user(user):
        return {
            "_id": str(user["_id"]),
            "username": user.get("username"),
            "permission_level": user.get("permission_level", 0)
        }

    # Middleware to check if logged in
    def login_required(f):
        from functools import wraps
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return decorated_function

    # Route: Home / Message board
    @app.route('/', methods=['GET', 'POST'])
    @login_required
    def index():
        if request.method == 'POST':
            content = request.form.get('content')
            if content:
                messages_col.insert_one({
                    "content": content,
                    "createdAt": time.time(),
                    "user_id": session['user_id']
                })
                flash('Message sent!', 'success')
                # Notify listeners about new message here if you implement pubsub
            else:
                flash('Message cannot be empty', 'error')

            return redirect(url_for('index'))

        # Fetch messages sorted by createdAt descending
        messages = list(messages_col.find().sort('createdAt', -1))
        return render_template('index.html', messages=messages)

    # Route: Login
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if 'user_id' in session:
            return redirect(url_for('index'))

        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            user = users_col.find_one({'username': username})
            if user and check_password_hash(user['password'], password):
                session['user_id'] = str(user['_id'])
                session['username'] = user['username']
                session['permission_level'] = user.get('permission_level', 0)
                session['theme'] = user.get('theme', 0)
                flash('Logged in successfully!', 'success')
                return redirect(url_for('index'))
            else:
                flash('Invalid username or password', 'error')

        return render_template('login.html')

    # Route: Signup
    @app.route('/signup', methods=['GET', 'POST'])
    def signup():
        if 'user_id' in session:
            return redirect(url_for('index'))

        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')

            if users_col.find_one({'username': username}):
                flash('Username already exists', 'error')
                return redirect(url_for('signup'))

            hashed_pw = generate_password_hash(password)
            user_id = users_col.insert_one({
                "username": username,
                "password": hashed_pw,
                "permission_level": 0,
                "theme": 0
            }).inserted_id

            flash('Account created! Please login.', 'success')
            return redirect(url_for('login'))

        return render_template('signup.html')

    # Route: Logout
    @app.route('/logout')
    @login_required
    def logout():
        session.clear()
        flash('Logged out successfully!', 'success')
        return redirect(url_for('login'))

    # Route: Admin dashboard
    @app.route('/admin', methods=['GET'])
    @login_required
    def admin_dashboard():
        if session.get('permission_level') != 1:
            flash('You do not have permission to access admin dashboard', 'error')
            return redirect(url_for('index'))

        users = list(users_col.find())
        users = [serialize_user(u) for u in users]
        messages = list(messages_col.find().sort('createdAt', -1))
        return render_template('admin.html', users=users, messages=messages)

    # Route: Update user permission (Admin only)
    @app.route('/admin/update_permission/<user_id>', methods=['POST'])
    @login_required
    def update_permission(user_id):
        if session.get('permission_level') != 1:
            flash('Permission denied', 'error')
            return redirect(url_for('index'))

        if user_id == session['user_id']:
            flash('You cannot change your own permission', 'error')
            return redirect(url_for('admin_dashboard'))

        new_level = int(request.form.get('permission_level', 0))
        users_col.update_one({'_id': ObjectId(user_id)}, {'$set': {'permission_level': new_level}})
        flash('User permission updated', 'success')
        return redirect(url_for('admin_dashboard'))

    # Route: Reset user password (Admin only)
    @app.route('/admin/reset_password/<user_id>', methods=['POST'])
    @login_required
    def reset_password(user_id):
        if session.get('permission_level') != 1:
            flash('Permission denied', 'error')
            return redirect(url_for('index'))

        if user_id == session['user_id']:
            flash('You cannot reset your own password here', 'error')
            return redirect(url_for('admin_dashboard'))

        new_password = "password123"  # default reset pw
        hashed_pw = generate_password_hash(new_password)
        users_col.update_one({'_id': ObjectId(user_id)}, {'$set': {'password': hashed_pw}})
        flash(f"Password reset to '{new_password}' for user", 'success')
        return redirect(url_for('admin_dashboard'))

    # Route: Delete user (Admin only)
    @app.route('/admin/delete_user/<user_id>', methods=['POST'])
    @login_required
    def delete_user(user_id):
        if session.get('permission_level') != 1:
            flash('Permission denied', 'error')
            return redirect(url_for('index'))

        if user_id == session['user_id']:
            flash('You cannot delete yourself', 'error')
            return redirect(url_for('admin_dashboard'))

        users_col.delete_one({'_id': ObjectId(user_id)})
        flash('User deleted', 'success')
        return redirect(url_for('admin_dashboard'))

    # Route: Delete message (Admin only)
    @app.route('/admin/delete_message/<message_id>', methods=['POST'])
    @login_required
    def delete_message(message_id):
        if session.get('permission_level') != 1:
            flash('Permission denied', 'error')
            return redirect(url_for('index'))

        messages_col.delete_one({'_id': ObjectId(message_id)})
        flash('Message deleted', 'success')
        return redirect(url_for('admin_dashboard'))

    # Route: Toggle theme
    @app.route('/toggle_theme', methods=['POST'])
    @login_required
    def toggle_theme():
        current = session.get('theme', 0)
        new_theme = 1 if current == 0 else 0
        session['theme'] = new_theme

        # Save to DB too (optional)
        users_col.update_one({'_id': ObjectId(session['user_id'])}, {'$set': {'theme': new_theme}})
        flash('Theme toggled', 'success')
        return redirect(request.referrer or url_for('index'))

    # Route: Reset password from user settings page
    @app.route('/settings/reset_password', methods=['POST'])
    @login_required
    def settings_reset_password():
        current_pw = request.form.get('current_password')
        new_pw = request.form.get('new_password')
        confirm_pw = request.form.get('confirm_password')

        user = users_col.find_one({'_id': ObjectId(session['user_id'])})

        if not user or not check_password_hash(user['password'], current_pw):
            flash('Current password is incorrect', 'error')
            return redirect(request.referrer or url_for('index'))

        if new_pw != confirm_pw:
            flash('New passwords do not match', 'error')
            return redirect(request.referrer or url_for('index'))

        hashed_pw = generate_password_hash(new_pw)
        users_col.update_one({'_id': ObjectId(session['user_id'])}, {'$set': {'password': hashed_pw}})
        flash('Password updated successfully', 'success')
        return redirect(request.referrer or url_for('index'))

    # SSE stream endpoint for live message updates
    @app.route('/stream')
    @login_required
    def stream():
        def event_stream():
            last_time = time.time()
            while True:
                # Fetch new messages since last_time (poll every 1 sec)
                new_msgs = list(messages_col.find({"createdAt": {"$gt": last_time}}).sort('createdAt', 1))
                if new_msgs:
                    for msg in new_msgs:
                        data = json.dumps(serialize_message(msg))
                        yield f"data: {data}\n\n"
                    last_time = new_msgs[-1]['createdAt']
                time.sleep(1)
        return Response(event_stream(), mimetype='text/event-stream')

    # Run app
    if __name__ == '__main__':
        app.run(debug=True)
