## Introduction
Facade API for Aretiico services

Aretiico backend consists of a number of services (ejbca, Positronic, etc..), each with their own native  low level interfaces, flavours and complexities. This API presents a set of business level REST endpoints suitable for consumption by front of house UIs such as the Portal.

It is implemented in Python, with the intention of defining the end points early and lifting these into to AWS Lambda. 

## Requirements
- Python >= 3.10

## Install
1.  Install Poetry : [https://python-poetry.org/docs/#installation](https://python-poetry.org/docs/#installation)
 
2.  Install dependencies: Run  `poetry install` to install the dependencies from  `poetry.toml`. This will create a virtual environment and install the dependencies inside.
    
3.  Activate virtual environment: run  `poetry shell`. 
    
4.  Run the project: `python main.py -u eng04.aretiico.dev -c portal@aretiico.dev.pem -s server.pem`.

## Configure
The application is configuration driven through `config.ini`. The EJBCA section already points to eng04 sandbox, and the certificates and administration private key are common for all `*.aretiico.dev` sandboxes.
Change the `192.168.50.253` address to reflect the IP or hostname of the box hosting the bridge. 
 # CA instance and credentials for administration
 [ejbca]
 address = https://eng04.aretiico.dev:8443
 server_certificate = ca_bundle.pem
 client_certificate = superadmin.pem
 client_key = superadmin.pem
  
 # Bridge server (i.e. us)
 [server]
 address = 192.168.50.253
  
## Run
Start the server with:
`python rest_api.py --config config.ini --verbose`
and see the Postman script `ca.postman_collection.json` for the sample REST calls.
