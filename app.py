
from flask import Flask, request, jsonify
from flask_cors import CORS
from pathlib import Path
from datetime import datetime

from scanner.scanner import scan_project
from database import initialize_database, save_scan, get_all_scans

app = Flask(__name__)

CORS(app, resources={
    r"/api/*": {
        "origins": [
            "http://127.0.0.1:5500",
            "http://localhost:5500",
            "null"
        ]
    }
})


@app.route("/")
def home():
    return jsonify({
        "application": "SecretShield",
        "status": "online",
        "message": "SecretShield API is running"
    })


@app.route("/api/history", methods=["GET"])
def scan_history():
    try:
        scans = get_all_scans()

        return jsonify({
            "total_scans": len(scans),
            "history": scans
        }), 200

    except Exception:
        app.logger.exception("History retrieval failed")

        return jsonify({
            "error": "Could not retrieve scan history"
        }), 500


@app.route("/api/scan", methods=["POST"])
def run_scan():
    data = request.get_json(silent=True) or {}
    project_path = data.get("project_path")

    if not project_path:
        return jsonify({
            "error": "Project path is required"
        }), 400

    try:
        project = Path(project_path).resolve()

        if not project.exists() or not project.is_dir():
            return jsonify({
                "error": "Invalid project directory"
            }), 400

        # Run scanner using standard Gitleaks rules.
        result = scan_project(str(project))

        scan_date = datetime.now().astimezone().isoformat(
            timespec="seconds"
        )

        # Save sanitized findings in SQLite.
        save_scan(
            str(project),
            scan_date,
            result["status"],
            result["total_secrets"],
            result["findings"]
        )

        return jsonify(result), 200

    except (ValueError, RuntimeError) as error:
        return jsonify({
            "error": str(error)
        }), 400

    except Exception:
        app.logger.exception("Unexpected scanning error")

        return jsonify({
            "error": "An unexpected scanning error occurred"
        }), 500


if __name__ == "__main__":
    initialize_database()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
