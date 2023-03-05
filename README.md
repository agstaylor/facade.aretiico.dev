
## Introduction
Facade API for Aretiico services

Aretiico consists of a number of services (EJBCA, Positronic, etc..), each with their own native low level interfaces, flavours and complexities. This API presents a set of business level endpoints suitable for consumption by front of house UIs such as the Portal.

It is implemented in Python, supporting a prototyping workflow and lifting into to AWS Lambda. 

## Requirements
- Python >= 3.10

## Install
1.  Install Poetry : [https://python-poetry.org/docs/#installation](https://python-poetry.org/docs/#installation)
 
2.  Install dependencies: Run  `poetry install` to install the dependencies from  `poetry.toml`. This creates a virtual environment and installs the dependencies inside.
    
3.  Activate virtual environment: run  `poetry shell`. 
    
4.  Run : `python app.py -u eng04.aretiico.dev -c portal@aretiico.dev.pem -s server.pem`.

## Parse certificates 

> Get for user aretiico_user

    curl --silent http://eng04.aretiico.dev:5000/endentity/certificates/aretiico_user

> Extract the first returned certificate

    curl --silent http://eng04.aretiico.dev:5000/endentity/certificates/aretiico_user | grep -oP '(?<="0": ")[^"]+'

> Convert to OpenSSL PEM

    curl --silent http://eng04.aretiico.dev:5000/endentity/certificates/aretiico_user | grep -oP '(?<="0": ")[^"]+' | sed -e '1s/^/-----BEGIN CERTIFICATE-----\n/' -e '$s/$/\n-----END CERTIFICATE-----/' -e 's/\\n/\n/g' > certificate.pem

> View

    openssl x509 -in certificate.pem -text

## Generate a server side key and issue certificate (pkcs#12)

> Pass in subject distinguished name (dn) and passphrase to encrypt resulting pkcs#12 

    curl --silent -X POST http://eng04.aretiico.dev:5000/certificate/pkcs12enroll/smime/aretiico_user -H "Content-Type: application/json" -d '{"password":"password", "dn":"E=ataylor@aretiico.dev,CN=Alastair Taylor,OU=Engineering,O=Aretiico,C=GB"}'

> Extract the returned keystore 

    curl --silent -X POST http://eng04.aretiico.dev:5000/certificate/pkcs12enroll/smime/aretiico_user
    -H "Content-Type: application/json" -d '{"password":"password", "dn":"E=ataylor@aretiico.dev,CN=Alastair Taylor,OU=Engineering,O=Aretiico,C=GB"}' | grep -oP '(?<="keystore": ")[^"]+'

> Extract the returned keystore and write to file keystore.p12

    curl --silent -X POST http://eng04.aretiico.dev:5000/certificate/pkcs12enroll/smime/aretiico_user
    -H "Content-Type: application/json" -d '{"password":"password", "dn":"E=ataylor@aretiico.dev,CN=Alastair Taylor,OU=Engineering,O=Aretiico,C=GB"}' | grep -oP '(?<="keystore": ")[^"]+' | tr -d '\n' | base64 -d > keystore.p12

> View keystore file in OpenSSL

    openssl pkcs12 -in keystore.p12 -info -nodes

## Issue certificate from an externally generated CSR (pkcs#10)

> Generate key pair and create PKCS#10 CSR

    openssl req -new -newkey rsa:2048 -nodes -out csr.pem -keyout private.key -subj "/C=UK/ST=/L=/O=Aretiico/OU=Engineering/CN=ataylor@aretiico.dev"

> View CSR

    openssl req -text -noout -verify -in csr.pem

