import logging
from typing import Set, List, Tuple

from cidemiasecurity.security import oauth2_scheme
from cidemiasecurity.security.models import UserModel
from cidemiasecurity.security.utils import get_current_user
from fastapi import HTTPException, FastAPI
from fastapi.dependencies.models import SecurityRequirement
from fastapi.routing import APIRoute
from starlette.status import HTTP_401_UNAUTHORIZED
from starlette.requests import Request
from starlette.types import Scope, Receive, Send, ASGIApp

from cidemiasecurity.urls.schemas import ApiUrl

auth_requirement = SecurityRequirement(oauth2_scheme, [])
no_auth_requirement: SecurityRequirement = None


log = logging.getLogger(__file__)


def has_one_permission(user: UserModel, permissions: Set[str]) -> bool:
    """
    This method will verify if a given user has one of permissions.
    There is a special permission named `authenticated` that will just look if the user is fully authenticated
    :param user: CTSUser -> The user
    :param permissions: Set[str] -> The list of permissions to look for
    :return: bool -> True if the user has one of the permissions, else otherwise
    """
    if "authenticated" in permissions:
        return True
    for permission in permissions:
        if permission in user.permissions:
            return True
    return False


def check_permissions_wrapper(app: ASGIApp, permissions: Set[str] = None) -> Tuple[ASGIApp, SecurityRequirement]:
    """
    This a wrapper method that will implement the check of permission before executing an app
    :param app: ASGIApp -> The input app
    :param permissions: List[str]
    :return:
    """
    if not permissions or len(permissions) == 0 or "anonymous" in permissions:
        return app, no_auth_requirement
    _app = getattr(app, "original_app", app)

    async def my_app(scope: Scope, receive: Receive, send: Send):
        request: Request = Request(scope, receive=receive)
        user: UserModel = await get_current_user(await oauth2_scheme(request))

        if user and has_one_permission(user, permissions):
            return await _app(scope, receive, send)
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    setattr(my_app, "original_app", _app)
    return my_app, auth_requirement


def generate_route_app(route: APIRoute, permissions: Set[str] = None):
    """
    Generate an app for this app by modifying its app and security requirements
    :param route: APIRoute -> The route
    :param permissions: Set[str] -> The set of permissions to secure this route
    :return:
    """
    app, security_requirement = check_permissions_wrapper(route.app, permissions)
    route.app = app
    if security_requirement and getattr(route, "security_requirement_added", False) is False:
        route.dependant.security_requirements.append(security_requirement)
        setattr(route, "security_requirement_added", True)


def url_method_key(url: str, method: str) -> str:
    """
    Generate a fake key based on url and method
    :param url: str -> The url
    :param method: str -> The method
    :return: str
    """
    return f"{method.lower()}-{url}"


def secure_app(app: FastAPI, api_urls: List[ApiUrl]):
    """
    This will secure all routes of a given app
    :param app: FastAPI -> The app
    :param api_urls: List[ApiUrl] -> List of securities an api url
    :return:
    """
    permissions_map = {url_method_key(api_url.method, api_url.url): api_url.permissions for api_url in api_urls}
    for route in app.routes:
        if isinstance(route, APIRoute):
            route: APIRoute

        if route.methods is None:
            route.methods = ["GET"]
        for method in route.methods:
            # ISSUE: if we have multiple HTTP methods on a route, the security defined on the last HTTP method
            # will only apply.
            try:
                permissions = permissions_map.get(url_method_key(method, route.path))
                generate_route_app(route, permissions)
            except KeyError:
                log.warning(f"Url {route.path} and method {method} is unknown to the URL security system")
