"""
REST validation schemas
"""

from marshmallow import Schema, fields


class EndEntitySchema(Schema):
    email = fields.Email(required=True)


class GetCertificatesSchema(Schema):
    onlyvalid = fields.Boolean(required=True)


class Pkcs12EnrollSchema(Schema):
    password = fields.Str(required=True)
    dn = fields.Str(required=True)


class Pkcs10EnrollSchema(Schema):
    request = fields.Str(required=True)
