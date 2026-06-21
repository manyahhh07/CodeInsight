from flask import Flask, render_template, request, jsonify
import dataclasses
from analyzer import analyze_code

app = Flask(__name__)


def to_dict(obj):
    if dataclasses.is_dataclass(obj):
        return dataclasses.asdict(obj)
    return obj


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    code = data.get("code", "").strip()
    language = data.get("language", "python").strip().lower()

    if not code:
        return jsonify({"error": "No code provided"}), 400

    result = analyze_code(code, language)
    return jsonify(to_dict(result))


if __name__ == "__main__":
    app.run(debug=True)