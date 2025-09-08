from flask import Flask, render_template, request, jsonify
import os
from src.email_parser import parse_email, EmailAnalysisError
from src.ai_integration import analyze_with_ai
from src.database_manager import DatabaseManager
import aiohttp
import asyncio
from config.config import CONFIG

app = Flask(__name__)

# Database manager for caching
db_manager = DatabaseManager(CONFIG.get("DATABASE_PATH"), CONFIG.get("CACHE_DURATION_SECONDS"))

# --- Landing page / Welcome page ---
@app.route('/')
def welcome():
    return render_template('welcome.html')

# --- Dashboard page ---
@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

# --- File upload & AI analysis ---
@app.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    # Save temporary file
    save_path = os.path.join("uploads", file.filename)
    os.makedirs("uploads", exist_ok=True)
    file.save(save_path)

    try:
        parsed = parse_email(save_path)
    except EmailAnalysisError as e:
        return jsonify({"error": str(e)}), 400

    # Run async AI analysis
    async def run_analysis():
        async with aiohttp.ClientSession() as session:
            return await analyze_with_ai(parsed, session)

    result = asyncio.run(run_analysis())
    return jsonify(result)

# --- Reports endpoint ---
@app.route("/reports", methods=["GET"])
def get_reports():
    # TODO: Load from DB when reports are cached
    return jsonify({"reports": []})

if __name__ == "__main__":
    app.run(debug=True)
