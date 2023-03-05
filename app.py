"""
Flask application for Aretiico facade REST API

!todo add Positronic
!todo add Authentication
!todo modularize via blueprints

example usage:
python app.py --url eng04.aretiico.dev --client portal@aretiico.dev.pem --server server.pem
python app.py --url ca.aretiico.dev --client portal@aretiico.dev.pem --server server.pem
"""
from flask import Flask, jsonify, request, make_response
from marshmallow import ValidationError
from ejbca_client.EjbcaClient import EjbcaClient
from cryptography import x509
import base64
from validation import (
    EndEntitySchema,
    GetCertificatesSchema,
    Pkcs10EnrollSchema,
    Pkcs12EnrollSchema,
)
import argparse

# Create parser object
parser = argparse.ArgumentParser(
    description="EJBCA REST", formatter_class=argparse.ArgumentDefaultsHelpFormatter
)

parser.add_argument("-c", "--client", type=str, help="client keystore")
parser.add_argument("-s", "--server", type=str, help="server certificate bundle")
parser.add_argument("-u", "--url", type=str, help="ejbca url")

# Check correct arguments were passed
args = parser.parse_args()
if (
    (not any(vars(args).values()))
    or (args.client is None)
    or (args.server is None)
    or (args.url is None)
):
    parser.print_help()
    exit()

print("url :", args.url)
print("client keystore :", args.client)
print("server certificate :", args.server)
print("--")

# Connect to ejbca backend
try:
    client = EjbcaClient(args.url, args.client, args.client, args.server)
    version = client.getEjbcaVersion()
    print(args.url + " | " + version + "\n")
except Exception as e:
    print(str(e))
    exit()

# create Flask app instance
app = Flask(__name__)

# -- EndEntity endpoints
# --


@app.route("/endentity/<username>", methods=["POST"])
def createEndEntity(username: str):
    """Create a new end entity for issuing certificates against

    Args:
        username (str): username or uuid
    """
    try:
        parameters = EndEntitySchema().load(request.json)
        client.addUser(username, parameters["email"])
        return jsonify({"result": "ok"}), 200
    except Exception as err:
        return jsonify({"result": str(err)}), 400


@app.route("/endentity/<username>", methods=["GET"])
def getEndEntity(username: str):
    try:
        user = client.findUser(username)
        if user:
            return jsonify({"result": "ok", "email": user["email"]}), 200
        else:
            return jsonify({"result": "user " + username + " does not exist"}), 400
    except Exception as err:
        return jsonify({"result": str(err)}), 400


@app.route("/endentity/<username>", methods=["PUT"])
def editEndEntity(username: str):
    try:
        parameters = EndEntitySchema().load(request.json)
        client.editUser(username, parameters["email"])
        return jsonify({"result": "ok"}), 200
    except Exception as err:
        return jsonify({"result": str(err)}), 400


@app.route("/endentity/<username>", methods=["DELETE"])
def deleteEndEntity(username: str):
    try:
        user = client.deleteUser(username)
        return jsonify({"result": "ok"}), 200
    except Exception as err:
        return jsonify({"result": str(err)}), 400


@app.route("/endentity/certificates/<username>", methods=["GET"])
def getEndEntityCertificates(username: str):
    """List all certificates issued against end entity

    {"onlyvalid" : "true"} - only show unrevoked certificates
    {"onlyvalid" : "false"} -  show valid and revoked certificates

    """
    try:
        parameters = GetCertificatesSchema().load(request.json)
        user = client.findUser(username)
        if not user:
            return jsonify({"result": "user " + username + " does not exist"}), 400
        certs = client.getCertificates(username, parameters["onlyvalid"])
        data = {}
        for i in range(len(certs)):
            data[i] = certs[i]["certificateData"].decode("ascii")
        return make_response(jsonify({"certificates": data}), 200)
    except Exception as err:
        return jsonify({"result": str(err)}), 400


# -- Certificate endpoints
# --


@app.route("/certificate/pkcs12enroll/smime/<username>", methods=["POST"])
def pkcs12enrollSmime(username: str):
    """Issue a certificate generating the key on the CA server

    {"dn" : "CN=example.com,O=Example Company,OU=IT,C=GB"} - full X.509 distinguished name for subject
    {"password" : "password"} - password to protect encrypted keystore

    Returns:
        pkcs#12 password keystore containing generated key, issued certificate and full chain
    """
    try:
        parameters = Pkcs12EnrollSchema().load(request.json)
        user = client.findUser(username)
        if not user:
            return jsonify({"result": "user " + username + " does not exist"}), 400

        p12 = client.p12enroll(username, parameters["dn"], parameters["password"])

        # Encode pkcs#12 for json
        encoded_p12 = base64.b64encode(p12).decode()
        return jsonify({"result": "ok", "keystore": encoded_p12}), 200
    except Exception as err:
        return jsonify({"result": str(err)}), 400


@app.route("/certificate/pkcs10enroll/smime/<username>", methods=["POST"])
def pkcs10enrollSmime(username):
    try:
        parameters = Pkcs10EnrollSchema().load(request.json)
        user = client.findUser(username)
        if not user:
            return jsonify({"result": "user " + username + " does not exist"}), 400

        csr = base64.b64decode(parameters["request"])
        dn = x509.load_der_x509_csr(csr).subject.rfc4514_string()
        certificate = client.p10enroll(username, dn, base64.b64encode(csr))
        return jsonify({"result": "ok", "certificate": certificate}), 200

    except ValidationError as err:
        return jsonify(err.messages), 400
    except Exception as err:
        return jsonify({"result": str(err)}), 400


@app.route("/ca/version", methods=["GET"])
def getEjbcaVersion():
    version = client.getEjbcaVersion()
    return jsonify({"result": "ok", "version": version}), 200


@app.route("/ca", methods=["GET"])
def getAvailableCAs():
    caList = client.getAvailableCAs()
    return jsonify({"result": "ok", "CAs": caList}), 200


@app.route("/ca/chain", methods=["GET"])
def getCAChain():
    chain = client._client.service.getLastCAChain("Aretiico UK Commercial Issuing")
    data = {}
    for i in range(len(chain)):
        data[i] = chain[i]["certificateData"].decode("ascii")

    return jsonify({"result": "ok", "certificates": data}), 200


# Run the Flask app
if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
