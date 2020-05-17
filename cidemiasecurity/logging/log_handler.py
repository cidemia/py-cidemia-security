import logging
import logging.config
import yaml


def load_file_config(file_name: str):
    """
        This function loads a log config file.
        To read more about the structure of the log file see https://realpython.com/python-logging/#other-configuration-methods
    """
    with open(file_name, 'r') as f:
        config = yaml.safe_load(f.read())
        logging.config.dictConfig(config)


def get_logger(name: str):
    """
        Get a logger with a given name
    """
    return logging.getLogger(name)


def test_logger():
    load_file_config('../log_config.yml')
    log = get_logger("TestClass")
    log.debug("1- This is a debug")
    log.info("2- This is a info")
    log.warning("3- This is a warn")
    log.error("4- This is an error")
    log.critical("5- this is critical")


if __name__ == '__main__':
    test_logger()
