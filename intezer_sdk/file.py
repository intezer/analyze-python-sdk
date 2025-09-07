from typing import IO
from typing import Optional
from typing import Union

from intezer_sdk import consts
from intezer_sdk._api import IntezerApi
from intezer_sdk.api import IntezerApiClient
from intezer_sdk.api import get_global_api
from intezer_sdk.index import Index


class File:
    """
    File is a class for file-related operations including indexing and downloading.
    It provides a unified interface for file management operations.
    """

    def __init__(self,
                 file_path: str = None,
                 sha256: str = None,
                 api: IntezerApiClient = None):
        """
        File is a class for file-related operations including indexing and downloading.

        :param file_path: The path to the file.
        :param sha256: The sha256 hash of the file.
        :param api: The API connection to Intezer.
        """
        if (sha256 is not None) == (file_path is not None):
            raise ValueError('Choose between sha256 or file_path')

        self._file_path = file_path
        self._sha256 = sha256
        self._api = IntezerApi(api or get_global_api())
        self._index: Optional[Index] = None

    @property
    def sha256(self) -> str:
        """Get the SHA256 hash of the file."""
        return self._sha256

    @property
    def file_path(self) -> str:
        """Get the file path."""
        return self._file_path

    def index(self,
              index_as: consts.IndexType,
              family_name: str = None,
              wait: Union[bool, int] = False):
        """
        Index the file.

        :param index_as: The type of the index (trusted or malicious).
        :param family_name: The family name to index as (mandatory if index_as is malicious).
        :param wait: Whether to wait for the indexing to complete.
        """
        if self._sha256:
            self._index = Index(sha256=self._sha256,
                                index_as=index_as,
                                family_name=family_name,
                                api=self._api.api)
        else:
            self._index = Index(file_path=self._file_path,
                                index_as=index_as,
                                family_name=family_name,
                                api=self._api.api)

        self._index.send(wait=wait)

    def unset_indexing(self, wait: Union[bool, int] = False):
        """
        Unset the indexing request (only works for sha256-based files).

        :param wait: Whether to wait for the operation to complete.
        """
        if not self._sha256:
            raise ValueError('Unset indexing is only supported for sha256-based files')

        if not self._index:
            self._index = Index(sha256=self._sha256,
                                index_as=consts.IndexType.TRUSTED,
                                api=self._api.api)

        self._index.unset_indexing(wait=wait)

    def wait_for_index_completion(self, interval: int = None, sleep_before_first_check=False):
        """
        Blocks until the index is completed.

        :param interval: The interval to wait between checks.
        :param sleep_before_first_check: Whether to sleep before the first status check.
        """
        if not self._index:
            raise ValueError('No index operation in progress')

        self._index.wait_for_completion(interval, sleep_before_first_check)

    def check_index_status(self):
        """
        Check the index status.

        :return: The index status code.
        """
        if not self._index:
            raise ValueError('No index operation in progress')

        return self._index.check_status()

    @property
    def index_status(self):
        """Get the current index status."""
        if not self._index:
            return None
        return self._index.status

    @property
    def index_id(self):
        """Get the index ID."""
        if not self._index:
            return None
        return self._index.index_id

    def download(self,
                 path: str = None,
                 output_stream: IO = None,
                 password_protection: str = None):
        """
        Download the file (only works for sha256-based files).

        ``path`` or ``output_stream`` must be provided.
        :param path: A path to where to save the file, it can be either a directory or non-existing file path.
        :param output_stream: A file-like object to write the file's content to.
        :param password_protection: Set password protection to download file as zip with password.
        """
        if not self._sha256:
            raise ValueError('Download is only supported for sha256-based files')

        self._api.download_file_by_sha256(self._sha256, path, output_stream, password_protection)
