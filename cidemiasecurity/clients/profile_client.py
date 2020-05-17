from cidemiasecurity.clients import MicroServiceClient
from cidemiasecurity.clients.models import Profile, ProfileUpdate, Permissions
from typing import List
from starlette.status import HTTP_422_UNPROCESSABLE_ENTITY
from fastapi import HTTPException


class ProfileClient(MicroServiceClient):
    def __init__(self):
        MicroServiceClient.__init__(self, "AUTH", "/api/profiles")

    def get_all_profiles(self) -> List[Profile]:
        return self._get_url("/")

    def get_profile_by_code(self, code: str) -> List[Profile]:
        return self._get_url(f"/{code}")

    def create_profile(self, profile: Profile) -> Profile:
        response = self._post_url("/", profile.dict(skip_defaults=True))
        if response.status_code == 201:
            return response.payload
        else:
            raise HTTPException(
                status_code=HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Error on created Profile")

    def update_profile(self, code: str, profile_update: ProfileUpdate) -> Profile:
        response = self._put_url(f"/{code}", profile_update.dict(skip_defaults=True))
        if response.status_code == 202:
            return response.payload
        else:
            raise HTTPException(
                status_code=HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Error on updated Profile")

    def remove_profile(self, code: str):
        return self._delete_url(f"/{code}", code)

    def add_permissions_to_profile(self, code: str, permissions: Permissions):
        return self._post_url(f"/{code}/permissions", permissions.dict())

    def remove_profile_role(self, code: str, permissions: Permissions):
        return self._delete_url(f"/{code}/permissions", permissions.dict())

    def get_permissions_by_profile(self, code: str) -> List[Permissions]:
        return self._get_url(f"/{code}/permissions")

    def update_profile_role(self, code: str, permissions: Permissions):
        return self._put_url(f"/{code}/permissions", permissions.dict())
