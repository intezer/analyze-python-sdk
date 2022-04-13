import warnings


def deprecated(message: str):
    def wrapper(func):
        warnings.warn(message,
                      DeprecationWarning,
                      stacklevel=2)
        return func

    return wrapper
