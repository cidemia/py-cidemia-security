from werkzeug.local import Local, release_local

local = Local()


def save_object_in_request(name: str, value):
    """
    This will save an object in the context of a request. It will be available along all the request
    :param name: str -> The name of the object to save
    :param value: The object to save
    """
    setattr(local, name, value)


def read_object_from_request(name: str):
    """
    This will read an object from the local context and send it.
    :param name: str -> The name under which the variable was saved
    :return: object
    :raises AttributeError
    """
    return getattr(local, name)


def read_object_from_request_safe(name: str):
    """
    Same as ```get_request_object``` but return None if not found
    :param name: str -> The name under which the variable was saved
    :return: object
    """
    try:
        return getattr(local, name)
    except AttributeError:
        return None


def release_request_object(name: str):
    try:
        return delattr(local, name)
    except AttributeError:
        return None


def release_request_objects():
    release_local(local)
