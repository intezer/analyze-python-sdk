import io
import os


def load_binary_file_from_resources(*file_name: str) -> io.BytesIO:
    path_to_file = os.path.join(os.path.dirname(__file__), 'resources', *file_name)
    with open(path_to_file, 'rb') as file:
        file_bytes = io.BytesIO(file.read())

    return file_bytes
