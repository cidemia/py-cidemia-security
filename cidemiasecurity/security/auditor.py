from datetime import datetime


class AuditorAware:
    """
    This class is used when dealing with auditable entities
    """

    def get_current_auditor(self) -> str:
        """
        returns the current auditor
        :return:
        """
        return None

    def get_current_time(self) -> datetime:
        return datetime.now()
