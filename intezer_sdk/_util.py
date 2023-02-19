import warnings


def deprecated(message: str):
    def decorator(func):
        def wrapper(*args, **kwargs):
            warnings.warn(message,
                          DeprecationWarning,
                          stacklevel=2)
            return func(*args, **kwargs)
        return wrapper

    return decorator
