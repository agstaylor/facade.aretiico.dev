# --url ca.aretiico.dev --client portal@aretiico.dev.pem --server server-root.pem
from flask import Flask, jsonify, request, make_response
from marshmallow import ValidationError
from ejbca_client.EjbcaClient import EjbcaClient
from cryptography import x509
import base64
from validation import EndEntityPostSchema, EndEntityPutSchema, Pkcs10EnrollSchema, Pkcs12EnrollSchema
import argparse

# Create parser object
parser = argparse.ArgumentParser(description='EJBCA REST', formatter_class=argparse.ArgumentDefaultsHelpFormatter)

parser.add_argument('-c', '--client', type=str, help='client keystore')
parser.add_argument('-s', '--server', type=str, help='server certificate bundel')
parser.add_argument('-u', '--url', type=str, help='ejbca url')

# Parse the arguments
args = parser.parse_args()

# Check if correct arguments were passed
if (not any(vars(args).values())) or (args.client is None) or (args.server is None) or (args.url is None):
    parser.print_help()
    exit()

# Parse the arguments
args = parser.parse_args()
print('url :', args.url)
print('client keystore :', args.client)
print('server certificate :', args.server)
print('--')

# Connect to ejbca backend
try:
    client = EjbcaClient(args.url, args.client, args.client, args.server)
    version = client.getEjbcaVersion()
    print(args.url + ' | ' + version + '\n')
except Exception as e:
    print(str(e))
    exit()

# create a Flask app instance
app = Flask(__name__)

# -- REST endpoints -- #

@app.route('/endentity', methods=['POST'])
def createEndEntity():
    try:
        entity = EndEntityPostSchema().load(request.json)
        client.addUser(entity['name'], entity['email'])

    except ValidationError as err:
        return jsonify(err.messages), 400
    except Exception as err:
        return jsonify({'result': str(err)}), 400

    return jsonify({'result': 'ok'}), 200

@app.route('/endentity/<username>', methods=['PUT'])
def editEndEntity(username):
    try:
        entity = EndEntityPutSchema().load(request.json)
        client.editUser(username, entity['email'])

    except ValidationError as err:
        return jsonify(err.messages), 400

    except Exception as err:
        return jsonify({'result': str(err)}), 400

    return jsonify({'result': 'ok'}), 200

@app.route('/endentity/<username>', methods=['GET'])
def getEndEntity(username):
    try:
        user = client.findUser(username)
        if not user:
            return jsonify({'result': 'user ' + username + ' does not exist'}), 400
    except ValidationError as err:
        return jsonify(err.messages), 400

    except Exception as err:
        return jsonify({'result': str(err)}), 400

    return jsonify({'result': 'ok', 'email':user['email']}), 200

@app.route('/endentity/<username>', methods=['DELETE'])
def deleteEndEntity(username):
    try:
        user = client.deleteUser(username)
    except Exception as err:
        return jsonify({'result': str(err)}), 400

    return jsonify({'result': 'ok'}), 200

@app.route('/endentity/certificates/<username>', methods=['GET'])
def getEndEntityCertificates(username):

    try:
        user = client.findUser(username)
        if not user:
            return jsonify({'result': 'user ' + username + ' does not exist'}), 400

        certs = client.getCertificates(username)

    except ValidationError as err:
        return jsonify(err.messages), 400

    except Exception as err:
        # print(str(err))
        return jsonify({'result': str(err)}), 400

    data = {}
    for i in range(len(certs)):
        data[i] = certs[i]['certificateData'].decode('ascii')

    return make_response(jsonify({'certificates': data}), 200)

    # return jsonify({'status': 'operation good'}), 200
    return certs, 200

@app.route('/certificate/pkcs12enroll/smime/<username>', methods=['POST'])
def pkcs12enrollSmime(username):
    try:
        parameters = Pkcs12EnrollSchema().load(request.json)
        user = client.findUser(username)
        if not user:
            return jsonify({'result': 'user ' + username + ' does not exist'}), 400

        # returns p12 as bytes        
        p12 = client.p12enroll(username, parameters['dn'], parameters['password'])

        # encode for json 
        encoded_p12 = base64.b64encode(p12).decode()
        return jsonify({'result': 'ok', 'keystore':encoded_p12}), 200

    except ValidationError as err:
        return jsonify(err.messages), 400
    except Exception as err:
        return jsonify({'result': str(err)}), 400


@app.route('/certificate/pkcs10enroll/smime/<username>', methods=['POST'])
def pkcs10enrollSmime(username):
    try:
        parameters = Pkcs10EnrollSchema().load(request.json)
        user = client.findUser(username)
        if not user:
            return jsonify({'result': 'user ' + username + ' does not exist'}), 400
        
        csr = base64.b64decode(parameters['request'])
        dn = x509.load_der_x509_csr(csr).subject.rfc4514_string()
        certificate = client.p10enroll(username, dn, base64.b64encode(csr))
        return jsonify({'result': 'ok', 'certificate':certificate}), 200

    except ValidationError as err:
        return jsonify(err.messages), 400
    except Exception as err:
        return jsonify({'result': str(err)}), 400


@app.route('/ca/version', methods=['GET'])
def getEjbcaVersion():
    version  = client.getEjbcaVersion()
    return jsonify({'result': 'ok', 'version':version}), 200

@app.route('/ca', methods=['GET'])
def getAvailableCAs():
    caList = client.getAvailableCAs()
    return jsonify({'result': 'ok', 'CAs':caList}), 200

@app.route('/ca/chain', methods=['GET'])
def getCAChain():
    chain = client._client.service.getLastCAChain('Aretiico UK Commercial Issuing')
    data = {}
    for i in range(len(chain)):
        data[i] = chain[i]['certificateData'].decode('ascii')

    return jsonify({'result': 'ok', 'certificates':data}), 200

# run the Flask app
if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
