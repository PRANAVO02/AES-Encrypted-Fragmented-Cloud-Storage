from flask import Flask, render_template, request, redirect, url_for, flash
import os
import json
import encrypt_and_upload
import download_and_decrypt

app = Flask(__name__)
app.secret_key = "super_secret_key"

REGISTRY_FILE = "manifests.json"

@app.route("/")
def index():
    # Load uploaded files from registry
    if os.path.exists(REGISTRY_FILE):
        with open(REGISTRY_FILE, "r") as f:
            files = list(json.load(f).keys())
    else:
        files = []
    return render_template("index.html", files=files)

@app.route("/upload", methods=["POST"])
def upload():
    if "file" not in request.files:
        flash("No file selected!", "danger")
        return redirect(url_for("index"))

    file = request.files["file"]
    if file.filename == "":
        flash("Please choose a valid file!", "danger")
        return redirect(url_for("index"))

    # Save uploaded file temporarily
    os.makedirs("uploads", exist_ok=True)
    file_path = os.path.join("uploads", file.filename)
    file.save(file_path)

    try:
        encrypt_and_upload.encrypt_and_upload(file_path, registry_file=REGISTRY_FILE)
        flash(f"File '{file.filename}' encrypted & uploaded successfully ✅", "success")
    except Exception as e:
        flash(f"Error uploading file: {str(e)}", "danger")

    return redirect(url_for("index"))

@app.route("/download", methods=["POST"])
def download():
    filename = request.form.get("filename")
    if not filename:
        flash("No filename provided!", "danger")
        return redirect(url_for("index"))

    try:
        reconstructed_path = download_and_decrypt.download_and_decrypt(filename, registry_file=REGISTRY_FILE)
        flash(f"File '{filename}' downloaded & decrypted successfully at '{reconstructed_path}' ✅", "success")
    except Exception as e:
        flash(f"Error downloading file: {str(e)}", "danger")

    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(debug=True)
