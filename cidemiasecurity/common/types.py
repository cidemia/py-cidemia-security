from typing import Union, List


class SingleOrMultiple:

    def __getitem__(self, cls):
        return Union[cls, List[cls]]
