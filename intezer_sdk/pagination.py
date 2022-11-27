from typing import List, Dict

from intezer_sdk.api import IntezerApi


class Pagination:
    def __init__(self, url: str, api: IntezerApi, data: Dict):
        """
        Store list of data into pages.
        :param api: Intezer api request for new page.
        :param url: Url to request new data from.
        :param data: Data
        """
        self.api = api
        self.data = data
        self.pages = []
        self._current_page = None
        self._url = url
        self._page_size = data["limit"]
        self._current_page_number = 0
        self._current_offset = 0
        self.total_count = 0
        self.row_number = 0
        self._fetch_page()

    def _fetch_page(self):
        """Request for new page from server."""
        self.data['offset'] = self._current_offset
        self.total_count, self._current_page = self.api._fetch_analyses_history(
            self._url, self.data)
        self._current_offset += self._page_size
        self.pages.append(self._current_page)
        self._current_page_number = len(self.pages)
        return self._current_page

    def __iter__(self):
        """Iterate for page."""
        yield from self._current_page
        self._fetch_page()
        if self._current_page:
            yield from self.__iter__()

    def __next__(self) -> List:
        """Move to next row."""
        try:
            next_row = next(self._current_page)
            self.row_number += 1
        except StopIteration:
            self.__iter__()
            next_row = next(self._current_page)
            self.row_number = 0
        return next_row

    @property
    def prev_page(self) -> List:
        """Move to the previus page."""
        if self._current_page_number - 1 >= 0:
            self._current_page_number -= 1
            self._current_page = self.pages[self._current_page_number]
            self.row_number = 0
        return self._current_page

    @property
    def next_page(self) -> List:
        """Move to the next page"""
        if self._current_page_number == len(self.pages) - 1:
            return self._fetch_page()
        self._current_page_number += 1
        self._current_page = self.pages[self._current_page_number]
        return self._current_page

    @property
    def __prev__(self) -> List:
        """Get previus row."""
        if self.row_number == 0:
            _ = self.prev_page
            return self.__next__()
        self.row_number -= 1
        return self._current_page[self.row_number]

    @property
    def all(self):
        """All rows as flat list."""
        rows = []
        for row in self.pages:
            rows.extend(row)
        return rows

    @property
    def current_page(self):
        if self._current_page:
            self._fetch_page()
        return self._current_page

    @staticmethod
    def _fetch_analyses_history(api, url_path, data):
        response = api.request_with_refresh_expired_access_token(path=url_path, method='POST', data=data)
        api.raise_for_status(response)
        return response.json()["total_count"], response.json()["analyses"]
