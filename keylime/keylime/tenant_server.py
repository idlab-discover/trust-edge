import argparse
from flask import Flask, request
import os
from keylime import tenant

app = Flask(__name__)

@app.route('/edgenode', methods=['POST'])
def process_zip():
    uuid = request.form.get('uuid')
    zip_file = request.files['file']

    mb_refstate = request.files['json'].read().decode('utf-8')
    command = "add"

    tenant.main(command ,mb_refstate, uuid, zip_file)

    return "Success"
def main():
    app.run(debug=False, port=5000, host='0.0.0.0')
