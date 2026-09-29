"""Cyber Incident Report Analyzer - Flask server.
Run:  python app.py   then open http://127.0.0.1:5000
Needs MongoDB running locally on mongodb://localhost:27017 (database: cyber_reports)."""
import datetime as dt

import gridfs
from bson import ObjectId
from bson.errors import InvalidId
from flask import Flask, jsonify, render_template, request
from pymongo import MongoClient, DESCENDING
from pymongo.errors import PyMongoError

import nlp_engine

MONGO_URI = "mongodb://localhost:27017"
DB_NAME = "cyber_reports"
MONGO_MSG = ("Cannot reach MongoDB at " + MONGO_URI + ". Please install and start MongoDB "
             "(for example run 'mongod' or start the MongoDB service) and try again.")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 40 * 1024 * 1024  # 40 MB upload limit
_client = None


def get_db():
    """Return the database, or raise PyMongoError if MongoDB is not running."""
    global _client
    if _client is None:
        _client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=2500)
    _client.admin.command("ping")
    return _client[DB_NAME]


def err(msg, code):
    return jsonify({"error": msg}), code


@app.errorhandler(413)
def too_large(_):
    return err("The file is too large (limit is 40 MB).", 413)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/analyze", methods=["POST"])
def analyze():
    f = request.files.get("file")
    if not f or not f.filename:
        return err("Please choose a PDF file first.", 400)
    data = f.read()
    if not f.filename.lower().endswith(".pdf") or not data.startswith(b"%PDF"):
        return err("Only PDF files are accepted. Please upload a .pdf file.", 400)
    try:
        db = get_db()  # check MongoDB first so the user gets a clear message early
    except PyMongoError:
        return err(MONGO_MSG, 503)
    try:
        report, text = nlp_engine.analyze_pdf(data)
    except ValueError as e:  # scanned / empty / corrupted / protected PDF
        return err(str(e), 422)
    except Exception as e:
        return err(f"Analysis failed: {e}", 500)
    try:
        pdf_id = gridfs.GridFS(db).put(data, filename=f.filename, content_type="application/pdf")
        res = db.reports.insert_one({
            "filename": f.filename, "uploaded_at": dt.datetime.utcnow(), "pdf_id": pdf_id,
            "text": text, "report": report, "charts": report["charts"]})
    except PyMongoError:
        return err(MONGO_MSG, 503)
    return jsonify({"id": str(res.inserted_id), "filename": f.filename, "report": report})


@app.route("/api/reports")
def list_reports():
    try:
        docs = get_db().reports.find({}, {"filename": 1, "uploaded_at": 1, "report.title": 1}).sort("uploaded_at", DESCENDING).limit(100)
        return jsonify([{"id": str(d["_id"]), "filename": d["filename"], "title": d.get("report", {}).get("title", ""),
                         "uploaded_at": d["uploaded_at"].strftime("%Y-%m-%d %H:%M UTC")} for d in docs])
    except PyMongoError:
        return err(MONGO_MSG, 503)


@app.route("/api/reports/<rid>")
def get_report(rid):
    try:
        doc = get_db().reports.find_one({"_id": ObjectId(rid)})
    except InvalidId:
        return err("Report not found.", 404)
    except PyMongoError:
        return err(MONGO_MSG, 503)
    if not doc:
        return err("Report not found.", 404)
    return jsonify({"id": rid, "filename": doc["filename"], "report": doc["report"],
                    "uploaded_at": doc["uploaded_at"].strftime("%Y-%m-%d %H:%M UTC")})


if __name__ == "__main__":
    print("Loading NLP models (first run may download the sentence-transformers model)...")
    try:
        nlp_engine.load_models()
    except RuntimeError as e:
        print("SETUP PROBLEM:", e)
        raise SystemExit(1)
    print("\nOpen this link in your browser:  http://127.0.0.1:5000\n")
    app.run(host="127.0.0.1", port=5000, debug=False)
