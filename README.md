# 🕵️‍♂️ Pulse Chat 💬

A Flask-based anonymous messaging web application with user authentication, admin management, message moderation, and live updates using Server-Sent Events (SSE). Hosted on Vercel with MongoDB as the database backend.

![App Preview](/api/static/images/replit/preview.PNG)

---

## 🚀 Features

* 🔐 User signup and login with secure password hashing
* ⏳ Account creation cooldown (10 minutes per device)
* ✍️ Message posting with markdown and syntax-highlighted code blocks
* 🚫 Restricted words filtering loaded from external file
* 🕔 Message cooldown (5 seconds between messages per user)
* 🛠️ Admin dashboard for user and message management
* 🛡️ Admin permissions to delete users, delete messages, reset passwords, and update permission levels
* 🎨 User theme toggle (light/dark mode)
* 🔄 Password reset for users and admins
* 🕛 Automatic daily clearing of messages at midnight UK time
* 📡 Live message streaming using Server-Sent Events (SSE)
* 🔑 Sessions with 7-day lifetime and permanent session management
* 🛡️ Input sanitization and XSS protection using MarkupSafe and custom formatting

---

## ☁️ Hosting & Deployment

* **Platform:** Vercel 🌐
* **Database:** MongoDB Atlas (cloud hosted) 🗄️
* **SVG Icons:** Sourced from [SVGRepo](https://www.svgrepo.com/) 🎨

---

## ⚙️ Installation and Setup

### Prerequisites

* 🐍 Python 3.7+
* ☁️ MongoDB Atlas cluster with connection URI
* 🔧 Vercel account and CLI configured for deployment

### Environment Variables

Create a `.env` file or set environment variables in your deployment environment with:

SECRET\_KEY=your\_super\_secret\_key\_here
MONGO\_URI=your\_mongodb\_connection\_string\_here

> ⚠️ **Note:** Never commit your secret keys or database credentials to public repositories.

### Local Setup

1. Clone the repository:

   ```
   git clone https://github.com/cdr-int/msg-system
   cd anonymous-messaging-app
   ```

2. Install dependencies:

   ```
   pip install -r requirements.txt
   ```

3. Create the restricted words file:
   Place a text file at `api/static/bad_words.txt` with one restricted word per line.

4. Run the application:

   ```
   python app.py
   ```

5. Access the app locally at `http://localhost:5000`

---

## 📝 Usage

* 👤 Sign up with a username and password (must be at least 6 characters, with uppercase, lowercase, and a digit).
* 💬 Log in and start posting messages anonymously.
* 🖋️ Messages support markdown, inline code, and syntax-highlighted code blocks.
* 🛠️ Admin users can access `/admin` dashboard to manage users and messages.
* 🎭 Toggle light/dark theme in settings.
* 🕛 Messages are cleared automatically at midnight UK time daily.
* 🌐 Messages update live via SSE on the main page.

---

## 💡 Code Highlights

* 🔒 **Password Hashing:** SHA-256 with `hashlib`
* 🗄️ **MongoDB Client:** `pymongo.MongoClient`
* ⏰ **Scheduler:** APScheduler to clear messages daily at midnight UK time
* 🛡️ **Security:** Input sanitization with MarkupSafe and regex-based markdown escaping
* 🔑 **Session Management:** Flask sessions with 7-day expiry
* ⚡ **Real-time:** SSE stream for live message updates
* 🛑 **Rate Limiting:** Per-user cooldowns on message sending and account creation
* 🛠️ **Admin Controls:** Permission-based actions, self-modification restrictions

---

## 📁 File Structure Overview

```
├── app.py                   # Main Flask application
├── requirements.txt         # Python dependencies
├── api/
│   └── static/
│       └── bad_words.txt    # Restricted words list
├── templates/
│   ├── index.html           # Main chat page
│   ├── login.html           # Login page
│   ├── signup.html          # Signup page
│   ├── admin.html           # Admin dashboard
│   └── privacy.html         # Privacy policy page
└── static/
    └── ...                 # CSS, JS, SVG icons (from SVGRepo)
```

---

## 🛡️ Notes

* 🔐 **Security:** This app uses SHA-256 hashing without salting for simplicity. For production, consider bcrypt or Argon2 with salt.
* 🗄️ **Database:** Replace MongoDB URI with your own connection string. Do not expose credentials publicly.
* 🔑 **Session Secret:** Set a strong secret key via environment variables in production.
* ⏳ **Cooldowns:** Implemented with server-side timestamps and client-side cookies.
* 🎨 **Themes:** Stored per user in MongoDB and reflected in sessions.

---

## 📜 License

MIT License - see `LICENSE` file for details.

---

## 📞 Contact

For questions or issues, please open an issue on the repository or contact the maintainer.

---

✨ **Enjoy anonymous chatting! 🚀**

![Chatting Illustration](/api/static/images/replit/chatting.jpg)

---