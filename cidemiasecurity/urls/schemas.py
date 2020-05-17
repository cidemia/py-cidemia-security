from enum import Enum
from typing import Set

from pydantic import BaseModel


class HttpMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    OPTIONS = "OPTIONS"
    HEAD = "HEAD"
    TRACE = "TRACE"


class ApiUrlUpdate(BaseModel):
    name: str = None
    permissions: Set[str] = set()

    def __str__(self):
        return f"name: {self.name}"


class ApiUrlCreate(ApiUrlUpdate):
    name: str
    operation_id: str = None
    method: HttpMethod = HttpMethod.GET
    url: str

    def __str__(self):
        return f"{ApiUrlUpdate.__str__(self)}, url: {self.url}, operation_id: {self.operation_id}"


class ApiUrl(ApiUrlCreate):
    service: str

    def __str__(self):
        return f"(service: {self.service}, {ApiUrlCreate.__str__(self)})"
