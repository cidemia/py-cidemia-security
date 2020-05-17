from cidemiasecurity.clients import MicroServiceClient
from cidemiasecurity.clients.models import Role, RoleUpdate
from typing import List
from starlette.status import HTTP_422_UNPROCESSABLE_ENTITY
from fastapi import HTTPException


class RoleClient(MicroServiceClient):
    def __init__(self):
        MicroServiceClient.__init__(self, "AUTH", "/api/permissions")

    def get_all_roles(self) -> List[Role]:
        return self._get_url("/")

    def get_role_by_code(self, code: str) -> List[Role]:
        return self._get_url(f"/{code}")

    def create_role(self, role: Role) -> Role:
        response = self._post_url("/", role.dict(skip_defaults=True))
        if response.status_code == 201:
            return response.payload
        else:
            raise HTTPException(
                status_code=HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Error on created Role")

    def update_role(self, code: str, role_update: RoleUpdate) -> Role:
        response = self._put_url(f"/{code}", role_update.dict(skip_defaults=True))
        if response.status_code == 202:
            return response.payload
        else:
            raise HTTPException(
                status_code=HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Error on updated Role")

    def remove_role(self, code: str):
        return self._delete_url(f"/{code}")
