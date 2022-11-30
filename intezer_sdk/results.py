from typing import List
from typing import Dict
from typing import Tuple

from intezer_sdk.api import IntezerApi
from intezer_sdk.api import raise_for_status


class Results:
    def __init__(self, url_path: str, api: IntezerApi, filters: Dict):
        """
        Store list of data into pages.
        :param url_path: Url to request new data from.
        :param api: Instance of public Intezer API for request server.
        :param filters: filtered data.
        """
        self.api = api
        self.filters = filters
        self._pages = []
        self._current_page = None
        self._url_path = url_path
        self._current_page_number = 0
        self.total_count = 0
        self._current_offset = 0

    def __iter__(self):
        """Iterate for page."""
        if not self._current_page:
            self._fetch_page()
        yield from self._current_page
        self._fetch_page()
        yield from iter(self)

    def current_page(self) -> List:
        """Get current page, if not exits, ask a new one from server."""
        return self._current_page or self._fetch_page()

    def all(self) -> List:
        """Return all exits analysis's from server."""
        self._fetch_all_pages()
        self._current_page_number = 0
        self._current_page = self._pages[0]

        return self._unite_all_pages_to_one(self._pages)

    def previous_page(self) -> List:
        """Move to the previous page."""
        if self._current_page_number - 1 >= 0:
            self._current_page_number -= 1
            self._current_page = self._pages[self._current_page_number]
        return self._current_page

    def next_page(self) -> List:
        """Move to the next page"""
        if self._current_page_number == len(self._pages) - 1:
            return self._fetch_page()
        self._current_page_number += 1
        self._current_page = self._pages[self._current_page_number]
        return self._current_page

    def _fetch_page(self) -> List:
        """Request for new page from server."""
        self.filters['offset'] = self._current_offset
        self.total_count, new_page = self._fetch_analyses_history(
            self._url_path, self.filters)

        if not new_page:
            raise StopIteration()
        self._current_page = new_page
        self._update_current_page_metadata()
        return self._current_page

    def _update_current_page_metadata(self):
        """Update all metadata about new current page."""
        self._current_offset += len(self._current_page)
        self._pages.append(self._current_page)
        self._current_page_number = len(self._pages) - 1

    def _fetch_all_pages(self):
        """Request for all missing pages didn't request yet."""
        while not len(self._pages) or (
                len(self._pages) * self.filters['limits'] < self.total_count):
            try:
                self._fetch_page()
            except StopIteration:
                break

    def _fetch_analyses_history(self, url_path: str, data: Dict
                                ) -> Tuple[int, List]:
        """
        Request from server filtered analyses history.
        :param url_path: Url to request new data from.
        :param data: filtered data.
        :return: Count of all results exits in filtered request and amount
        analyses as requested.
        """
        response = self.api.request_with_refresh_expired_access_token(
            path=url_path, method='POST', data=data)
        raise_for_status(response)
        data_response = response.json()
        return data_response['total_count'], data_response['analyses']

    @staticmethod
    def _unite_all_pages_to_one(all_pages: List[List]) -> List:
        all_analysises = []
        for page in all_pages:
            all_analysises.extend(page)
        return all_analysises
