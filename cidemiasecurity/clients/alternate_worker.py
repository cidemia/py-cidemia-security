from typing import Dict, Any

import requests


class ApiResponse:
    def __init__(self, status_code: int = None, payload: Any = None, headers: Dict[str, Any] = None):
        self.status_code: int = status_code
        self.payload: str = payload
        self.headers: Dict[str, Any] = headers
        self.error: Any = None


class ApiResponseError(Exception):
    def __init__(self, status_code, message):
        self.status_code = status_code
        self.message = message


def _walker_generator(method: str, headers: Dict[str, str], data: Dict = None, params: Dict = None,
                      json: Any = None, **kwargs):

    def walker(url) -> ApiResponse:
        response = requests.request(method.lower(), url, json=json, headers=headers, data=data, params=params,
                                    **kwargs)
        api_response = ApiResponse(response.status_code, headers=response.headers)
        try:
            api_response.payload = response.json()
        except:
            pass
        return api_response

    if method.lower() not in ("post", "put", "get", "delete", "head", "options"):
        raise ValueError(f"Method {method} not handled")
    return walker
