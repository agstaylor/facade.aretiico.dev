"""A one-line summary of the module or program, terminated by a period.

Leave one blank line.  The rest of this docstring should contain an
overall description of the module or program.  Optionally, it may also
contain a brief description of exported classes and functions and/or usage
examples.

Typical usage example:

  foo = ClassFoo()
  bar = foo.FunctionBar()
"""

import base64
from enum import Enum
import requests
import zeep

from ejbca_client.EjbcaClientException import EjbcaClientException

# available type of user match criteria
# https://download.primekey.se/docs/EJBCA-Enterprise/latest/ws/org/ejbca/core/protocol/ws/client/gen/UserMatch.html
EJBCA_CONSTANTS_USER_MATCH = dict(
    {
        'MATCH_TYPE_BEGINSWITH': 1,
        'MATCH_TYPE_CONTAINS': 2,
        'MATCH_TYPE_EQUALS': 0,
        'MATCH_WITH_USERNAME': 0,
    }
)

# endentity revocation reason
# https://download.primekey.se/docs/EJBCA-Enterprise/latest/ws/org/ejbca/core/protocol/ws/client/gen/RevokeStatus.html
EJBCA_CONSTANTS_REVOCATION_REASON = dict(
    {
        'NOT_REVOKED': -1,
        'AACOMPROMISE': 10,
        'AFFILIATIONCHANGED': 3,
        'CACOMPROMISE': 2,
        'CERTIFICATEHOLD': 6,
        'CESSATIONOFOPERATION': 5,
        'KEYCOMPROMISE': 1,
        'PRIVILEGESWITHDRAWN': 9,
        'REMOVEFROMCRL': 8,
        'SUPERSEDED': 4,
        'UNSPECIFIED': 0,
    }
)

# ejbca endentity status constants
EJBCA_CONSTANTS_ENDENTITY_STATUS = dict(
    {
        10: 'NEW',  # New user
        11: 'FAILED',  # Generation of user certificate failed
        20: 'INITIALIZED',  # User has been initialized
        30: 'INPROCESS',  # Generation of user certificate in process
        40: 'GENERATED',  # A certificate has been generated for the user
        50: 'REVOKED',  # The user has been revoked and should not have any more certificates issued
        60: 'HISTORICAL',  # The user is old and archived
        70: 'KEYRECOVERY',  # The user is should use key recovery functions in next certificate generation.
        80: 'WAITINGFORADDAPPROVAL',  # the operation is waiting to be approved before execution.
    }
)

# type of certification request
# https://download.primekey.se/docs/EJBCA-Enterprise/latest/ws/org/ejbca/core/protocol/ws/client/gen/RevokeStatus.html
EJBCA_CONSTANTS_REQUEST_TYPE = dict(
    {
        'CRMF': 1,
        'PKCS10': 0,
        'PUBLICKEY': 3,
        'SPKAC': 2,
    }
)

class UserDataVOWS:
    STATUS_FAILED = 11
    STATUS_GENERATED = 40
    STATUS_HISTORICAL = 60
    STATUS_INITIALIZED = 20
    STATUS_INPROCESS = 30
    STATUS_KEYRECOVERY = 70
    STATUS_NEW = 10
    STATUS_REVOKED = 50
    TOKEN_TYPE_JKS = 'JKS'
    TOKEN_TYPE_P12 = 'P12'
    TOKEN_TYPE_PEM = 'PEM'
    TOKEN_TYPE_USERGENERATED = 'USERGENERATED'

class UserMatch(Enum):
    MATCH_TYPE_BEGINSWITH = 1
    MATCH_TYPE_CONTAINS = 2
    MATCH_TYPE_EQUALS = 0
    MATCH_WITH_CA = 5
    MATCH_WITH_CERTIFICATEPROFILE = 4
    MATCH_WITH_COMMONNAME = 101
    MATCH_WITH_COUNTRY = 112
    MATCH_WITH_DN = 7
    MATCH_WITH_DNSERIALNUMBER = 102
    MATCH_WITH_DOMAINCOMPONENT = 111
    MATCH_WITH_EMAIL = 1
    MATCH_WITH_ENDENTITYPROFILE = 3
    MATCH_WITH_GIVENNAME = 103
    MATCH_WITH_INITIALS = 104
    MATCH_WITH_LOCALE = 109
    MATCH_WITH_ORGANIZATION = 108
    MATCH_WITH_ORGANIZATIONUNIT = 107
    MATCH_WITH_STATE = 110
    MATCH_WITH_STATUS = 2
    MATCH_WITH_SURNAME = 105
    MATCH_WITH_TITLE = 106
    MATCH_WITH_TOKEN = 6
    MATCH_WITH_UID = 100
    MATCH_WITH_USERNAME = 0


class AlgorithmConstants:
    KEYALGORITHM_DSA = "DSA"
    KEYALGORITHM_DSTU4145 = "DSTU4145"
    KEYALGORITHM_EC = "EC"
    KEYALGORITHM_ECDSA = "ECDSA"
    KEYALGORITHM_ECGOST3410 = "ECGOST3410"
    KEYALGORITHM_RSA = "RSA"
    KEYSPECPREFIX_ECGOST3410 = "GostR3410-"
    SIGALG_GOST3411_WITH_DSTU4145 = "GOST3411withDSTU4145"
    SIGALG_GOST3411_WITH_ECGOST3410 = "GOST3411withECGOST3410"
    SIGALG_MD5_WITH_RSA = "MD5WithRSA"
    SIGALG_SHA1_WITH_DSA = "SHA1WithDSA"
    SIGALG_SHA1_WITH_ECDSA = "SHA1withECDSA"
    SIGALG_SHA1_WITH_RSA = "SHA1WithRSA"
    SIGALG_SHA1_WITH_RSA_AND_MGF1 = "SHA1withRSAandMGF1"
    SIGALG_SHA224_WITH_ECDSA = "SHA224withECDSA"
    SIGALG_SHA256_WITH_ECDSA = "SHA256withECDSA"
    SIGALG_SHA256_WITH_RSA = "SHA256WithRSA"
    SIGALG_SHA256_WITH_RSA_AND_MGF1 = "SHA256withRSAandMGF1"
    SIGALG_SHA3_256_WITH_ECDSA = "SHA3-256withECDSA"
    SIGALG_SHA3_256_WITH_RSA = "SHA3-256withRSA"
    SIGALG_SHA3_384_WITH_ECDSA = "SHA3-384withECDSA"
    SIGALG_SHA3_384_WITH_RSA = "SHA3-384withRSA"
    SIGALG_SHA3_512_WITH_ECDSA = "SHA3-512withECDSA"
    SIGALG_SHA3_512_WITH_RSA = "SHA3-512withRSA"
    SIGALG_SHA384_WITH_ECDSA = "SHA384withECDSA"
    SIGALG_SHA384_WITH_RSA = "SHA384WithRSA"
    SIGALG_SHA384_WITH_RSA_AND_MGF1 = "SHA384withRSAandMGF1"
    SIGALG_SHA512_WITH_ECDSA = "SHA512withECDSA"
    SIGALG_SHA512_WITH_RSA = "SHA512WithRSA"
    SIGALG_SHA512_WITH_RSA_AND_MGF1 = "SHA512withRSAandMGF1"

class CertificateHelper:
    CERT_REQ_TYPE_CRMF = 1
    CERT_REQ_TYPE_PKCS10 = 0
    CERT_REQ_TYPE_PUBLICKEY = 3
    CERT_REQ_TYPE_SPKAC = 2
    RESPONSETYPE_CERTIFICATE = "CERTIFICATE"
    RESPONSETYPE_PKCS7 = "PKCS7"
    RESPONSETYPE_PKCS7WITHCHAIN = "PKCS7WITHCHAIN"    


class TokenType(Enum):
    P12 = 1
    P10 = 2


class EjbcaClient:

    """ High level inteface to the EJBCA SOAP Web Service

        WSDL, connect to a running instance, i.e:
        python -mzeep http://ca.aretiico.dev:8080/ejbca/ejbcaws/ejbcaws?wsdl
    """

    # Use properties here, we cant hen adapt to dynamic loading from the various returned
    # lists from ejbca depending on the configuration of the specific rbac tls token

    @property
    def caName(self):
        return self.__caName

    @caName.setter
    def caName(self, v):
        self.__caName = v

    @property
    def endEntityProfile(self):
        return self.__endEntityProfile

    @endEntityProfile.setter
    def endEntityProfile(self, v):
        self.__endEntityProfile = v

    @property
    def certificateProfile(self):
        return self.__certificateProfile

    @certificateProfile.setter
    def certificateProfile(self, v):
        self.__certificateProfile = v

    # Defaults from the initial UK setup, profile names will change over time
    # ideally, the tls token will have RBAC configured in such a manner that
    # only one CA and limited profiles will ever be returned

    _default_ca = 'Aretiico UK Commercial Issuing'
    _default_endEntityProfile = 'EMPTY'
    _default_certificateProfile = 'ENDUSER'

    def __init__(
        self, url: str, client_key: str, client_certificate: str, server_certificate: str,
        ca=_default_ca,
        endEntityProfile=_default_endEntityProfile,
        certificateProfile=_default_certificateProfile
    ):
        """
        Args:
            url - base ejbca server url, without path or http/https
            client_key - pem client key for authentication to server
            client_certificate - pem clientcertificate for authentication to server
            server_certificate - server root certificate for tls connection
        """

        self.ca = ca
        self.endEntityProfile = endEntityProfile
        self.certificateProfile = certificateProfile

        # -- setup underlying https
        _https_session = requests.Session()
        _https_session.verify = server_certificate
        _https_session.cert = (client_certificate, client_key)
        _transport = zeep.transports.Transport(session=_https_session)

        self._client = zeep.Client(
            'https://' + url + ':8443/ejbca/ejbcaws/ejbcaws?wsdl',
            transport=_transport,
        )

    def getEjbcaVersion(self) -> str:
        """
        Returns : EJBCA version string from connected instance
        """
        response = self._client.service.getEjbcaVersion()
        return response

    def addUser(self, username: str, email: str):
        """
        Add the initial end entity record,
        Most values here are overridden when issuing
        """
        try:

            _user = self.findUser(username)
            if _user:
                raise EjbcaClientException(f'user {username} already exists')

            # Initial throwaways
            userDataVOWS = self._client.get_type('{http://ws.protocol.core.ejbca.org/}userDataVOWS')
            user = userDataVOWS()
            user.caName = self.ca
            user.username = username
            user.password = 'null'
            user.clearPwd = False
            user.email = email
            user.subjectDN = 'CN=' + username
            user.tokenType = UserDataVOWS.TOKEN_TYPE_USERGENERATED
            user.keyRecoverable = False
            user.sendNotification = False
            user.status = UserDataVOWS.STATUS_NEW
            user.endEntityProfileName = self.endEntityProfile
            user.certificateProfileName = self.certificateProfile

            self._client.service.editUser(user)

        except zeep.exceptions.Fault as e:
            raise EjbcaClientException(str(e))

        return

    def findUser(self, username: str) -> dict:
        """
        Returns : User record if found
        """
        try:
            _query = {
                'matchvalue': username,
                'matchtype': EJBCA_CONSTANTS_USER_MATCH['MATCH_TYPE_EQUALS'],
                'matchwith': EJBCA_CONSTANTS_USER_MATCH['MATCH_WITH_USERNAME'],
            }
            response = self._client.service.findUser(_query)
        except zeep.exceptions.Fault as e:
            raise EjbcaClientException(str(e))

        if response:
            return response[0]

    def editUser(self, username: str, email: str):
        """
        Edit user 
        """
        try:
            _user = self.findUser(username)
            if not _user:
                raise EjbcaClientException(f'user {username} not found')

            # Modify end entity record to allow issuance from a p10
            # note: ejbca required entity record to be STATUS_NEW for new cert
            _user['email'] = email
            self._client.service.editUser(_user)

        except zeep.exceptions.Fault as e:
            raise EjbcaClientException(str(e))

    def deleteUser(self, username: str):
        """
        Delete user and revoke all certificates
        """
        try:
            _user = self.findUser(username)
            if not _user:
                raise EjbcaClientException(f'user {username} not found')

            # revoke and delete all certificates ('true')
            self._client.service.revokeUser(username, EJBCA_CONSTANTS_REVOCATION_REASON['UNSPECIFIED'], 'true')

        except zeep.exceptions.Fault as e:
            raise EjbcaClientException(str(e))

    def p10enroll(self, username: str, dn: str, csr: bytes):
        """
        Issue certificate from pkcs#10 certificate request
        """
        try:
            _user = self.findUser(username)
            if not _user:
                raise EjbcaClientException(f'user {username} not found')

            # Modify end entity record to allow issuance from a p10
            # note: ejbca required entity record to be STATUS_NEW for new cert
            _user['subjectDN'] = dn
            _user['tokenType'] = UserDataVOWS.TOKEN_TYPE_USERGENERATED
            _user['status'] = UserDataVOWS.STATUS_NEW
            self._client.service.editUser(_user)

            response = self._client.service.certificateRequest(
                _user, 
                csr, 
                CertificateHelper.CERT_REQ_TYPE_PKCS10, 
                None, 
                CertificateHelper.RESPONSETYPE_CERTIFICATE
            )

            # certificate = "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n"
            # certificate = certificate.format(response["data"].decode())
            certificate = response["data"].decode()

            return certificate

        except zeep.exceptions.Fault as e:
            raise EjbcaClientException(str(e))
    
    def p12enroll(self, username: str, dn: str, password:str) -> bytes:
        """
        Issue certificate as pkcs#12 from distinguised name
        """
        try:
            _user = self.findUser(username)
            if not _user:
                raise EjbcaClientException(f'user {username} not found')

            # modify end entity record to allow p12 issuance
            _user['subjectDN'] = dn
            _user['password'] = password
            _user['tokenType'] = UserDataVOWS.TOKEN_TYPE_P12
            _user['status'] = UserDataVOWS.STATUS_NEW
            self._client.service.editUser(_user)

            response = self._client.service.pkcs12Req(username, password, None, '2048', AlgorithmConstants.KEYALGORITHM_RSA)
            return base64.b64decode(response["keystoreData"])

        except zeep.exceptions.Fault as e:
            raise EjbcaClientException(str(e))

    def getAvailableCAs(self) -> list:
        """
        Returns : List of CAs available to this authenticated client
        """
        # -- ns0:nameAndId(id: xsd:int, name: xsd:string)
        response = self._client.service.getAvailableCAs()
        return zeep.helpers.serialize_object(response, dict)

    def getAvailableCertificateProfiles(self, eeProfileId: int) -> list:
        """
        Returns : Certificate profiles available to EE
        """
        response = self._client.service.getAvailableCertificateProfiles(eeProfileId)
        return zeep.helpers.serialize_object(response, dict)

    def getAuthorizedEndEntityProfiles(self) -> list:
        """
        Returns : List of EE profiles available to this authenitcated client
        """
        try:
            response = self._client.service.getAuthorizedEndEntityProfiles()
        except zeep.exceptions.Fault as e:
            raise EjbcaClientException(str(e))

        return zeep.helpers.serialize_object(response, dict)

    def getCertificates(self, username: str) -> list:
        try:
            r = self._client.service.findCerts(username, 'false')
            return r
        except zeep.exceptions.Fault as e:
            raise EjbcaClientException(str(e))
