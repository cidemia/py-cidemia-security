from typing import Optional, List

from cidemiasecurity.holders.request_context_holder import save_object_in_request, read_object_from_request_safe, \
    release_request_objects
from cidemiasecurity.security.models import UserModel
from cidemiasecurity.security.utils import get_current_user_optional


class SecurityContextHolder:
    """
    This class is for holding security information during the request
    Every request has its own context
    """

    @staticmethod
    async def save_current_token(token: Optional[str]):
        """
        Save the token and eventually the corresponding user
        :param token: str -> the token to save
        """
        save_object_in_request("current_token", token)
        user = await get_current_user_optional(token)
        SecurityContextHolder.save_current_user(user)

    @staticmethod
    def get_current_token() -> Optional[str]:
        """
        Get the current token of the connected user
        :return: str
        """
        return read_object_from_request_safe("current_token")

    @staticmethod
    def save_current_user(user: Optional[UserModel]):
        """
        Save the current user
        :param user: CTSUser -> The user to save
        :return:
        """
        save_object_in_request("current_user", user)

    @staticmethod
    def get_current_user() -> Optional[UserModel]:
        """
        Get currently connected user. We need to register the user at the begining of the request by calling
        ```save_current_user```
        :return: CTSUser
        """
        return read_object_from_request_safe("current_user")

    @staticmethod
    def get_current_user_login() -> Optional[str]:
        """
        Get the login for currently connected user
        :return: str
        """
        user = SecurityContextHolder.get_current_user()
        if user:
            return user.username
        return None

    @staticmethod
    def is_logged_in() -> bool:
        """
        Tells if the user is registered and logged in
        :return: bool
        """
        return SecurityContextHolder.get_current_user() is not None

    @staticmethod
    def get_current_user_permissions() -> List[str]:
        """
        Get the list of permissions from the currently connected user
        :return: List[str]
        """
        user = SecurityContextHolder.get_current_user()
        if user:
            return user.permissions
        else:
            return []

    @staticmethod
    def current_user_has_permission(permission: str) -> bool:
        """
        Tells if the currently logged user has the given permission
        :param permission: str -> The permission to search against the user
        :return: bool
        """
        user = SecurityContextHolder.get_current_user()
        if user:
            return permission in user.permissions
        else:
            return False

    @staticmethod
    def release_context():
        release_request_objects()
