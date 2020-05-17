from typing import List

from cidemiasecurity.clients import MicroServiceClient
from cidemiasecurity.clients.models import UserCreation, User, UserUpdate, PasswordChange, Entities, PasswordResetEnd, Profiles, Offices, Permissions
from starlette.status import HTTP_422_UNPROCESSABLE_ENTITY
from fastapi import HTTPException


class UserClient(MicroServiceClient):
    def __init__(self):
        MicroServiceClient.__init__(self, "AUTH", "/api/users")

    def get_all_users(self, page: int = 1, per_page: int = None, token: str = None) -> List[User]:
        headers = self.default_headers
        if token:
            headers.update({"Authorization": f"Bearer {token}"})
        params = {"page": page, "per_page": per_page}
        return self._get_url("/", params, headers=headers)

    def get_current_user(self, token: str = None) -> User:
        headers = self.default_headers
        if token:
            headers.update({"Authorization": f"Bearer {token}"})
        return self._get_url("/me", headers=headers)

    def create_user(self, user: UserCreation) -> User:

        response = self._post_url("/", user.dict(skip_defaults=True))
        if response.status_code == 201:
            return response.payload
        else:
            raise HTTPException(
                status_code=HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Error on created User")

    def get_user(self, login: str) -> User:
        return self._get_url(f"/{login}")

    def update_user(self, login: str, user: UserUpdate) -> User:
        response = self._put_url(f"/{login}", user.dict(skip_defaults=True))
        if response.status_code == 202:
            return response.payload
        else:
            raise HTTPException(
                status_code=HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Error on updated User")

    def activate_user(self, login: str) -> bool:
        return self._put_url(f"/{login}/activate", None)

    def deactivate_user(self, login: str) -> bool:
        return self._put_url(f"/{login}/deactivate", None)

    def reset_user_password(self, login: str) -> bool:
        return self._get_url(f"/{login}/passwordreset")

    def validate_user_password_reset(self, login: str, token: str, new_password: str, new_password_confirm: str) -> bool:
        data = {"token": token, "new_password": new_password, "confirm_new_password": new_password_confirm}
        response = self._put_url(f"/{login}/passwordreset", data)
        if response.status_code == 202:
            return response.payload
        else:
            return False

    def change_password(self, login: str, change_data: PasswordChange, token: str = None) -> bool:
        headers = self.default_headers
        if token:
            headers.update({"Authorization": f"Bearer {token}"})
        response = self._put_url("/passwordchange", change_data.dict(skip_defaults=True), headers=headers)
        if response.status_code == 202:
            return response.payload
        else:
            raise HTTPException(
                status_code=HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Error on changed password")

    def validate_user(self, login: str) -> bool:
        return self._put_url(f"/{login}/validate", None)

    def search_user(self, param: str, token: str = None) -> User:
        headers = self.default_headers
        params = {"param": param}
        if token:
            headers.update({"Authorization": f"Bearer {token}"})
        return self._get_url("/search", params=params, headers=headers)

    def rest_user_password_init(self, login: str) -> bool:
        return self._get_url(f"/{login}/passwordreset", None)

    def rest_user_password_end(self, login: str, reset_data: PasswordResetEnd) -> bool:
        return self._put_url(f"/{login}/passwordreset", reset_data.dict(skip_defaults=True))

    def add_managed_customers(self, login: str, managed_customers: Entities):
        return self._post_url(f"/{login}/managed-customers", managed_customers.dict())

    def remove_managed_customers(self, login: str, customers: Entities):
        return self._delete_url(f"/{login}/managed-customers", customers.dict())

    def update_managed_customer(self, login: str, customers: Entities):
        return self._put_url(f"/{login}/managed-customers", customers.dict())

    def add_offices(self, login: str, offices: Offices):
        return self._post_url(f"/{login}/offices", offices.dict())

    def remove_offices(self, login: str, stale_offices: Offices):
        return self._delete_url(f"/{login}/offices", stale_offices.dict())

    def update_user_office(self, login: str, offices: Offices):
        return self._put_url(f"/{login}/offices", offices.dict())

    def add_permissions_to_user(self, login: str, permissions: Permissions):
        return self._post_url(f"/{login}/permissions", permissions.dict())

    def update_user_permissions(self, login: str, permissions: Permissions):
        return self._put_url(f"/{login}/permissions", permissions.dict())

    def remove_permissions_to_user(self, login: str, permissions: Permissions):
        return self._delete_url(f"/{login}/permissions", permissions.dict())

    def get_permissions_by_user(self, login: str):
        return self._get_url(f"/{login}")

    def create_user_profile(self, login: str, profiles: Profiles):
        return self._post_url(f"/{login}/profiles", profiles.dict())

    def add_user_offices(self, login: str, offices: Offices):
        return self._post_url(f"/{login}/offices", offices.dict())

    def remove_user_profile(self, login: str, profiles: Profiles):
        return self._delete_url(f"/{login}/profiles", profiles.dict())
