class UserError(Exception):
    def __init__(self, login: str):
        self.login = login


class UserNotFoundError(UserError):
    def __init__(self, login: str):
        super().__init__(login)

    def __str__(self):
        return f"user {self.login} not found"


class UserLockedError(UserError):
    def __init__(self, login: str):
        super().__init__(login)

    def __str__(self):
        return f"user {self.login} is locked"


class UserNotValidError(UserError):
    def __init__(self, login: str):
        super().__init__(login)

    def __str__(self):
        return f"user {self.login} is not valid"


class UserAlreadyExistsError(UserError):
    def __init__(self, login: str):
        super().__init__(login)

    def __str__(self):
        return f"user {self.login} already exists"


class PasswordExpiredError(UserError):
    def __init__(self, login: str):
        super().__init__(login)

    def __str__(self):
        return f"password for user {self.login} is expired"


class AuthenticationError(UserError):
    def __init__(self, login: str):
        super().__init__(login)

    def __str__(self):
        return f"Authentication error for user {self.login}."
