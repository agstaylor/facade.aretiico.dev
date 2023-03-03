"""
 Some examples to drive the client API
"""
from ejbca_client.EjbcaClient import EjbcaClient
import argparse
from cryptography import x509
import base64

from ejbca_client.EjbcaClientException import EjbcaClientException

# Create parser object
parser = argparse.ArgumentParser(
    description='End Entity Utility', formatter_class=argparse.ArgumentDefaultsHelpFormatter)

parser.add_argument('-c', '--client', type=str, help='client keystore')
parser.add_argument('-s', '--server', type=str, help='server certificate bundle')
parser.add_argument('-u', '--url', type=str, help='ejbca soap api url')

# Parse the arguments
args = parser.parse_args()

# Check correct arguments were passed
if (not any(vars(args).values())) or (args.client is None) or (args.server is None) or (args.url is None):
    parser.print_help()
    exit()

# Connect to ejbca backend
args = parser.parse_args()
try:
    client = EjbcaClient(args.url, args.client, args.client, args.server)
    version = client.getEjbcaVersion()
    print(f'Connected to {args.url} | {client.getEjbcaVersion()}')

    print(client.ca)
    print(client.endEntityProfile)
    print(client.certificateProfile)

    # -- add if not found
    user = client.findUser('ataylor')
    print(user if user else client.addUser('ataylor', 'agstaylor@gmail.com'))

# openssl req -new -newkey rsa:2048 -nodes -out csr.pem -keyout private.key -subj "/C=UK/ST=/L=/O=Aretiico/OU=Engineering/CN=ataylor@aretiico.dev"
# openssl req -in csr.pem -text
# sed -n '/-----BEGIN CERTIFICATE REQUEST-----/,/-----END CERTIFICATE REQUEST-----/p' csr.pem | sed '1d;$d' | tr -d '\n'

    # request = 'MIICmjCCAYICAQAwVTELMAkGA1UEBhMCVUsxETAPBgNVBAoMCEFyZXRpaWNvMRQwEgYDVQQLDAtFbmdpbmVlcmluZzEdMBsGA1UEAwwUYXRheWxvckBhcmV0aWljby5kZXYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDcnRgeBQRJSnByJQRIFgS018nujx1vCI540JkYITulWJvuXxV8Fp/ePYqnC9a9DMGOAOykRrUJFXQdbyHxiScNQSXOW8eL23lI1zjEAd52o9J95PHHrVfBQ4ZRDJJK0lhjG0i/xPodJDg21g2uvfGB4S9wrCdTMkZm3o2KjiM3ASg2kZ58keSRUi0hdrown79+29CHhe49CrFxoDpBhHBSHxCPSUlrS6f3Jwg+Pzl0Iul1jwnJCp0tiaMHuop1u8kJgBJVUZaT14pUKacFECiso+DZmXFUS3GyW+NNSouQLIcvEHBc8VNMS5UGNVwG/peGUOUrPX0q+XtLQHVCkPadAgMBAAGgADANBgkqhkiG9w0BAQsFAAOCAQEAnHrq74124XAIaot9yTj6BKsH/z7/4ZwKICNv7zPEU6wtoIFg7Q9ej/SfKFZFZK+c+GJVfW1KVDtzXmH3bX9prtvC3a7SrIb/auDXNUgMBQXd9IMU5MY8WlBJUBx66idPZwKmFu6G6zTf3RpAZSuXqeqI66JM6crTCjI+OxCRXx64WOAWPLrK2GuPC/AMuCi6UGYvh5EizOyD+w/ZIQM+KWA5rqp2dj0f5VnD/fordFIo1cm5A+8Zrf9YRBpY3ogwCIe6draUrlTJPjaFzRXVsrHvIEKfZhGDTu+oMJdYPaEtP5b0Za+n3O3tbrKS6U9cG7h3p68Gn1D4QdEjfTQNNw=='
    # print(base64.b64decode(request))
    # dn = x509.load_der_x509_csr(base64.b64decode(request)).subject.rfc4514_string()
    # print(f'dn : {dn}')

    # Extract the subject distinguished name
    with open("csr.pem", 'rb') as f:
        csr_bytes = f.read()
    dn = x509.load_pem_x509_csr(csr_bytes).subject.rfc4514_string()
    print(f'dn : {dn}')

    certificate = client.p10enroll('ataylor', dn, csr_bytes)
    print(certificate)
    with open('certificate.pem', 'w') as f:
        f.write(certificate)
    # openssl x509 -in certificate.pem -text

    p12 = client.p12enroll('ataylor', "CN=ataylor@hotmail.com,OU=Engineering,O=Aretiico,C=UK", 'password')
    print(p12)
    with open('keystore.p12', 'wb') as f:
        f.write(p12)

    # openssl pkcs12 -in keystore.p12 -info -nodes        

    # # -- find user (to confirm dn, new and p10 tokenType)
    # user = client.findUser('ataylor')
    # print(user)

    # #certificate = client.p12enroll('ataylor', "CN=p12@hotmail.com,OU=Engineering,O=Aretiico,C=UK", 'password')
    # # -- find user (to confirm dn, new and p12 tokenType)
    # user = client.findUser('ataylor')
    # print(user)

    #client.deleteUser('ataylor')

except EjbcaClientException as e:
    print(str(e))
    exit()
