from typing import List

from cidemiasecurity.clients.alternate_worker import ApiResponseError
from cidemiasecurity.urls.schemas import ApiUrl, ApiUrlUpdate, ApiUrlCreate, HttpMethod
from cidemiasecurity.clients import MicroServiceClient


class ApiUrlClient(MicroServiceClient):
    """
    This client will handle everything about API urls
    """
    def __init__(self):
        MicroServiceClient.__init__(self, "AUTH", "api/security/urls")

    def create_url(self, service: str, api_url: ApiUrlCreate) -> ApiUrl:
        """
        create a new Api URL
        :param service: str -> The service to which this url belongs
        :param api_url: ApiUrlCreate -> The information about the api url
        :return: ApiUrl -> The created API url
        """
        response = self._post_url(f"/{service}", api_url.dict(skip_defaults=True))
        if response.status_code == 201:
            return response.payload
        else:
            raise ApiResponseError(response.status_code, response.payload)

    def batch_create_service_urls(self, service: str, api_urls: List[ApiUrlCreate]) -> List[ApiUrl]:
        """
        Create on the fly many API urls
        :param service: str -> The service to which urls belong
        :param api_urls: List[ApiUrlCreate] -> List of information about api urls
        :return: List[ApiUrl] -> Created API urls
        """
        data = [api_url.dict(skip_defaults=True) for api_url in api_urls]
        response = self._post_url(f"/{service}/batch-create", data)
        if response.status_code == 201:
            return response.payload
        else:
            raise ApiResponseError(response.status_code, response.payload)

    def get_service_urls(self, service: str) -> List[ApiUrl]:
        """
        Get all API urls belonging to a given service
        :param service: str -> The service
        :return: List[ApiUrl] -> All API urls belonging to that service
        """
        response = self._get_url(f"/{service}")
        if response.status_code == 200:
            return [ApiUrl(**data) for data in response.payload]
        else:
            raise ApiResponseError(response.status_code, response.payload)

    def get_all_urls(self) -> List[ApiUrl]:
        """
        Get all API urls whatever their services
        :return: List[ApiUrl] -> List of API urls
        """
        response = self._get_url("/")
        if response.status_code == 200:
            return [ApiUrl(**data) for data in response.payload]
        else:
            raise ApiResponseError(response.status_code, response.payload)

    def update_service_url(self, service: str, operation_id: str, method: HttpMethod, url_update: ApiUrlUpdate) -> ApiUrl:
        """
        Update an API url infos
        :param service: str -> The service
        :param operation_id: str -> The operation id identifying the action
        :param method: HttpMethod -> the HTTP method corresponding to the action
        :param url_update: ApiUrlUpdate -> The update infos
        :return: ApiUrl -> The updated API url
        """
        response = self._put_url(f"/{service}/{operation_id}/{method}", url_update.dict(skip_defaults=True))
        if response.status_code == 202:
            return response.payload
        else:
            raise ApiResponseError(response.status_code, response.payload)

    def get_service_url(self, service: str, operation_id: str, method: HttpMethod) -> ApiUrl:
        """
        Get an API url
        :param service: str -> The service
        :param operation_id: str -> The operation id identifying the action
        :param method: HttpMethod -> the HTTP method corresponding to the action
        :return: ApiUrl -> The API url
        """
        response = self._get_url(f"/{service}/{operation_id}/{method}")
        if response.status_code == 200:
            return ApiUrl(**response.payload)
        else:
            raise ApiResponseError(response.status_code, response.payload)

    def delete_service_url(self, service: str, operation_id: str, method: HttpMethod) -> bool:
        """
        Delete an API url
        :param service: str -> The service
        :param operation_id: str -> The operation id identifying the action
        :param method: HttpMethod -> the HTTP method corresponding to the action
        :return: bool -> To tell if it is deleted or not
        """
        response = self._delete_url(f"/{service}/{operation_id}/{method}", None)
        if response.status_code == 202:
            return True
        else:
            raise ApiResponseError(response.status_code, response.payload)
