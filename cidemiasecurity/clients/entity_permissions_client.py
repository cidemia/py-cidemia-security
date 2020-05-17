from cidemiasecurity.clients import MicroServiceClient
from cidemiasecurity.clients.models import Profiles, Permissions
from typing import List


class EntityPermissionClient(MicroServiceClient):
    def __init__(self):
        MicroServiceClient.__init__(self, "AUTH", "/api/entities")

    def create_entity_profile(self, entity_code: str, profiles: Profiles):
        return self._post_url(f"/{entity_code}/profile", profiles)

    def remove_entity_profile(self, entity_code: str, profiles: Profiles):
        return self._delete_url(f"/{entity_code}/profile", profiles)

    def get_entity_profiles(self, entity_code: str) -> List[str]:
        return self._get_url(f"/{entity_code}/profile")

    def create_entity_permissions(self, entity_code: str, permissions: Permissions):
        return self._post_url(f"/{entity_code}/entity", permissions)

    def update_entity_role(self, entity_code: str, permissions: Permissions):
        return self._put_url(f"/{entity_code}/permissions", permissions)

    def remove_entity_permissions(self, entity_code: str, permissions: Permissions):
        return self._delete_url(f"/{entity_code}/entity", permissions)

    def get_permissions_by_entity(self, entity_code: str):
        return self._get_url(f"/{entity_code}/permissions", None)

    def get_roles_and_profiles_by_entity(self, entity_code: str):
        return self._get_url(f"/{entity_code}/permissions-and-profiles", None)

    def get_users_by_entity(self, entity_code: str):
        return self._get_url(f"/{entity_code}/users", None)
