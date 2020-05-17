from datetime import datetime
from typing import Optional, List

from pydantic import BaseModel


class AuditableEntity:
    created_date: datetime
    created_by: str
    last_updated: datetime
    last_updated_by: str


class LogicalDelete:
    deleted: bool
    deleted_by: str
    deleted_date: datetime


class UserModel(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None
    entity: Optional[str] = None
    permissions: Optional[List[str]] = None
    managed_entities: Optional[List[str]] = None
    entity_groups: Optional[List[str]] = None
    is_super_entity_staff: Optional[bool] = None
    is_entity_admin: Optional[bool] = None
    force_change_password: Optional[bool] = False
    impersonator: Optional[str] = None

    def is_impersonated(self):
        return self.impersonator is not None


class RefreshTokenInfo(BaseModel):
    origin: str
    access_token: str = None
    access_token_hash: str = None
