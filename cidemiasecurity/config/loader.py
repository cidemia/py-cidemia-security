import os
from typing import Any

from starlette.config import Config

__config = Config(os.path.join(os.getcwd(), ".env"))


def get_config(key: str, default: Any = None, cast: Any = None) -> Any:
    return __config.get(key, cast, default)


def set_config(key: str, value: Any):
    __config.environ.__setitem__(key, value)
