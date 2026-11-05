🚀 TONIX HTTPS — Complete Setup Guide

A simple guide to install and run the project using Termux.

«🔐 Important: Keep your GitHub token and API keys private. Never add real secrets to this README.»

---

📱 1. Update Termux
```
pkg update && pkg upgrade -y
```
🛠️ 2. Install Required Tools
```
pkg install git python nano -y
```
Check that Git and Python are installed:
```
git --version
python --version
```
---

📥 3. Clone the Private Repository
```
git clone https://github.com/tonixtoolkitofficial-afk/TONIX-HTTPS.git
```
Open the project folder:
```
cd TONIX-HTTPS
```
---

📦 4. Install Python Requirements

First, upgrade pip:
```
python -m pip install --upgrade pip
````
Then install project requirements:
```
pip install -r requirements.txt
```
«If the project does not contain "requirements.txt", this command may not work.»

---

🔑 5. Add Your Private Keys Safely

Create a private ".env" file:
```
nano .env
```
Add your own credentials:
```
GITHUB_TOKEN=PASTE_YOUR_TOKEN_HERE
GEMINI_API_KEY=PASTE_YOUR_GEMINI_API_KEY_HERE
```
Save in Nano:

1. Press CTRL + O → Press Enter
2. Press CTRL + X to exit

---

🔒 6. Protect Your Private Keys

Make sure ".env" is ignored by Git:

echo ".env" >> .gitignore

Check your Git status:

git status

Your ".env" file should not appear in the files waiting to be uploaded.

---

▶️ 7. Run the Tool

Depending on your project's main file:
```
python main.py
```
If your project uses a different startup file, replace "main.py" with the correct filename.

---

🌐 8. Website URL Input

Only test websites that you own or have permission to test.

Example format:
````
https://example.com
````
---

🤖 AI Report Setup

The project can use your Gemini API key from the local ".env" file to help generate and organize reports.

Make sure your ".env" file contains:
```
GEMINI_API_KEY=PASTE_YOUR_GEMINI_API_KEY_HERE
```
---

🔄 Update the Project

Download the latest changes:
```
git pull origin main
```
---

⬆️ Save Your Changes to GitHub

Check changes:

git status

Add changes:

git add .

Create a commit:

git commit -m "Update project"

Upload changes:

git push origin main

---

🛠️ Extra Useful Commands

See all files
``
ls -la
``
Go back one folder
```
cd ..
```
Check the current folder
``
pwd
``
View Git remote URL
```
git remote -v
```
View recent commits
```
git log --oneline -5
```
---

🔐 Security Rules

❌ Never upload:

- GitHub Personal Access Tokens
- Gemini API keys
- Passwords
- ".env" files

If a secret is accidentally shared, revoke it and create a new one.

---

🎉 Done!

Your project is now ready to install, configure, and run from Termux.

Happy Coding! 🚀
