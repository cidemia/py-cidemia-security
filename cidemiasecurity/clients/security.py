import requests
import json
from typing import List
from cidemiasecurity.config.loader import get_config
from cidemiasecurity.urls.schemas import ApiUrl, ApiUrlCreate
from cidemiasecurity.clients.alternate_worker import ApiResponseError
AUTH_URL = get_config("AUTH_URL")


class ApiUrlClient():
    def __init__(self, base_url):
        self.base_url = base_url

    def get_service_urls(self, service: str) -> List[ApiUrl]:
        url = f"{self.base_url}/api/security/urls/{service}"
        response = requests.get(url)
        if response.status_code == 200:
            return [ApiUrl(**data) for data in json.loads(response.content)]
        else:
            raise ApiResponseError(response.status_code, response.content)

    def create_url(self, service: str, api_url: ApiUrlCreate) -> ApiUrl:
        url = f"{self.base_url}/api/security/urls/{service}"
        api_url.permissions = list(api_url.permissions)
        response = requests.post(url, json.dumps(api_url.dict(skip_defaults=True)))
        if response.status_code == 201:
            return response.status_code
        else:
            raise ApiResponseError(response.status_code, response.content)

    def batch_create_service_urls(self, service: str, api_urls: List[ApiUrlCreate]) -> List[ApiUrl]:
        url = f"{self.base_url}/api/security/urls/{service}/batch-create"
        data = []
        for api_url in api_urls:
            api_url.permissions = list(api_url.permissions)
            data.append(api_url)
        data_url = json.dumps([ob.dict(skip_defaults=True) for ob in data])
        response = requests.post(url, data_url)
        if response.status_code == 201:
            return response.status_code
        else:
            raise ApiResponseError(response.status_code, response.content)
