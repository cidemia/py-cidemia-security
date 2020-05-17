from typing import List, Union

# from cidemiasecurity.common.types import SingleOrMultiple
from cidemiasecurity.security.models import UserModel


# Permissions = SingleOrMultiple[str]
Permissions = Union[str, List[str]]


def check_permissions(permissions: Permissions, permission_list: List[str]):
    if isinstance(permissions, str):
        permissions = [permissions]
    _permission_references = ["connected", "authenticated"] + permission_list
    return any([p in _permission_references for p in permissions])


def get_sub_entity(entity):
    return entity.split("_")[0] if entity else None


def check_user_access(user: UserModel, entity: str, sub_entity: str, simple_permissions: str, managed_permissions: str,
                      entity_permissions: str, global_permissions: str) -> bool:
    """
    Verify if a user has access to an entity based on permissions
    :param user: UserModel -> The user
    :param entity: str -> The entity
    :param sub_entity: str -> A sub entity
    :param simple_permissions: str -> As simple user, the permissions needed to have access
    :param managed_permissions: str -> As a super entity staff, the permissions needed to have access to managed entities
    :param entity_permissions: str -> As entity admin, permissions needed to have access to the entity
    :param global_permissions: str -> As a super entity staff, the permissions needed to have access to every entity
    :return: bool
    """
    if not user:
        return False
    user_entity = user.entity
    managed_entities = user.managed_entities
    # if sub entity is set, do comparisons with sub entities and not entities
    if sub_entity:
        user_entity = get_sub_entity(user_entity)
        managed_entities = [get_sub_entity(mc) for mc in managed_entities]
        entity = sub_entity
    # Super entity staff
    if user.is_super_entity_staff:
        # have appropriate global permissions
        if check_permissions(global_permissions, user.permissions):
            return True
        # Have appropriate permission can access its managed entities
        if entity in managed_entities and check_permissions(managed_permissions, user.permissions):
            return True
    if user_entity == entity:
        # admin of a entity with good permission have access to that entity
        if user.is_entity_admin and check_permissions(entity_permissions, user.permissions):
            return True
        # simple user with good permission have access to its entity
        if check_permissions(simple_permissions, user.permissions):
            return True
    return False
