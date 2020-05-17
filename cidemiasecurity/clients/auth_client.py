from cidemiasecurity.clients import MicroServiceClient


class AuthClient(MicroServiceClient):
    def __init__(self):
        MicroServiceClient.__init__(self, "AUTH", "/api/auth")

    def authenticate(self, username: str, password: str):
        return self._post_url("/", {"username": username, "password": password}, {})
