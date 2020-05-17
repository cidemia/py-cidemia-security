from cidemiasecurity.urls.schemas import HttpMethod


class ApiUrlNotFound(Exception):
    def __init__(self, service: str, url: str, method: HttpMethod, operation_id: str):
        self.service = service
        self.url = url
        self.operation_id = operation_id
        self.method = method

    def __str__(self):
        return f"url {self.url} not exists for method {self.method} and service {self.service}"


class ApiUrlAlreadyExists(Exception):
    def __init__(self, service: str, url: str, method: HttpMethod):
        self.service = service
        self.url = url
        self.method = method

    def __str__(self):
        return f"url {self.url} already exists for method {self.method} and service {self.service}"
