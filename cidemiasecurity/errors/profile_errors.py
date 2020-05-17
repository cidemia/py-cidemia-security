class ProfileError(Exception):
    def __init__(self, code: str):
        self.code = code


class ProfileNotFoundError(ProfileError):
    def __init__(self, code: str):
        super().__init__(code)

    def __str__(self):
        return f"Profile {self.code} not found"


class ProfileAlreadyExistsError(ProfileError):
    def __init__(self, code: str, owner: str):
        super().__init__(code)
        self.owner = owner

    def __str__(self):
        return f"Profile with code {self.code} and owner: {self.owner} has already exists"
