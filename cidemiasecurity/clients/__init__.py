import logging
from typing import Dict, Any

import py_eureka_client.eureka_client as eureka_client

from cidemiasecurity.clients.alternate_worker import _walker_generator
from cidemiasecurity.config.loader import get_config
from cidemiasecurity.security.random import generate_nonce

log = logging.getLogger(__file__)


def internal_get_config(current_value, name, env_name, raise_error: bool = False, caster=None):
    if not current_value:
        current_value = get_config(env_name, None)
        if raise_error and not current_value:
            log.error(f"Halt registering Eureka client. Either give the {name} or set {env_name} environment")
            raise ValueError
        log.warning(f"No {name}. Will use {current_value} read from {env_name} environment")

    return caster(current_value) if (caster and current_value) else current_value


async def init_client(eureka_url: str = None, application_name: str = None, instance_port: int = None,
                      instance_id: str = None, instance_host: str = None, instance_ip: str = None):
    """
    The flowing code will register your server to eureka server and also start to send heartbeat every 30 seconds
    :param eureka_url: str -> The URL of the Eureka server
    :param application_name: str -> The application name
    :param instance_port: int -> The instance port
    :param instance_id: str -> The instance id
    :param instance_host: str -> The instance host
    :param instance_ip: str -> The instance ip
    :return:
    """
    try:
        eureka_url = internal_get_config(eureka_url, "Eureka URL", "EUREKA_URL", True)
        application_name = internal_get_config(application_name, "Application name", "APP_NAME", True)
        instance_port = internal_get_config(instance_port, "instance port given", "APP_PORT", False, int)
    except ValueError as e:
        log.error(f"Error when starting Eureka. Lack of parameter: {str(e)}")
        return False
    if not instance_id:
        instance_id = f"{application_name}:{generate_nonce(21)}"
        log.warning(f"Not instance id given. Will use {instance_id}")
    if not instance_host:
        instance_host = internal_get_config(None, "Domain name", "DOMAIN_NAME", False) or ""
    log.info(f"Registering {application_name} to Eureka: {eureka_url}")
    eureka_client.init(eureka_server=eureka_url, app_name=application_name, instance_port=instance_port,
                       instance_id=instance_id, instance_host=instance_host, ha_strategy=eureka_client.HA_STRATEGY_STICK)


class MicroServiceClient:
    """
    Base class for handling calls to micro services
    """
    def __init__(self, service_name: str, base_url: str):
        self.service_name = service_name
        self.base_url = base_url
        self.default_headers = {"Content-Type": "application/json", "Accept": "application/json"}

    def _get_url(self, suffix_url, params: Dict[str, Any] = None, headers: Dict[str, Any] = None):
        # return eureka_client.do_service(self.service_name, self.base_url + suffix_url, headers=headers, return_type="json")
        return eureka_client.walk_nodes(self.service_name, self.base_url + suffix_url,
                                        walker=_walker_generator("get", params=params, headers=headers))

    def _post_url(self, suffix_url, data, headers=None):
        return eureka_client.walk_nodes(self.service_name, self.base_url + suffix_url,
                                        walker=_walker_generator("post", json=data, headers=headers))

    def _put_url(self, suffix_url, data, headers=None):
        return eureka_client.walk_nodes(self.service_name, self.base_url + suffix_url,
                                        walker=_walker_generator("put", json=data, headers=headers))

    def _delete_url(self, suffix_url, data, headers=None):
        return eureka_client.walk_nodes(self.service_name, self.base_url + suffix_url,
                                        walker=_walker_generator("delete", json=data, headers=headers))
