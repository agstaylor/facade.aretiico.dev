from marshmallow import Schema, fields


# Define schema for ee input data
class EndEntityPostSchema(Schema):
    name = fields.Str(required=True)
    email = fields.Email(required=True)


class EndEntityPutSchema(Schema):
    email = fields.Email(required=True)


class Pkcs12EnrollSchema(Schema):
    password = fields.Str(required=True)
    dn = fields.Str(required=True)

class Pkcs10EnrollSchema(Schema):
    request = fields.Str(required=True)
