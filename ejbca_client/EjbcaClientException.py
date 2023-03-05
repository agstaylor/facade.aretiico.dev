""" Exception class for EJBCA client """


class EjbcaClientException(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)
