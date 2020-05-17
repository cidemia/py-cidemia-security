import logging
from typing import List

from fastapi import FastAPI
from fastapi.routing import APIRoute

from cidemiasecurity.urls.schemas import ApiUrl

log = logging.getLogger(__file__)


def create_operation_id_from_url(url):
    """
    Create an operation based on the given url
    :param url: str -> The URL
    :return: str
    """
    return url.replace("/", "_").replace("{", "").replace("}", "")


def inspect_app(app: FastAPI, app_name: str) -> List[ApiUrl]:
    """
    Inspect an app to detect all declared routes
    :param app: FastAPI -> The fast api app
    :param app_name: str -> The app or service name
    :return: List[ApiUrl] -> The detected list of API urls
    """
    log.debug(f"Inspecting routes of app {app.title}")
    urls = []
    for route in app.routes:
        if isinstance(route, APIRoute):
            operation_id = create_operation_id_from_url(route.path)
            if route.operation_id:
                route: APIRoute
                operation_id = route.operation_id
            for method in route.methods:
                api_url = ApiUrl(url=route.path, name=route.name, permissions=[], method=method,
                                 service=app_name, operation_id=operation_id)
                urls.append(api_url)
                log.debug(f"found URL {str(api_url)}")
    return urls
