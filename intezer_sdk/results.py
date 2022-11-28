from typing import List, Dict, Tuple


class Results:
    def __init__(self, url: str, api: "IntezerApi", data: Dict):
        """
        Store list of data into pages.
        :param url: Url to request new data from.
        :param api: Istance of publice intezer api for request server.
        :param data: filtered data.
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

    def _fetch_page(self) -> List:
        """Request for new page from server."""
        self.data['offset'] = self._current_offset
        self.total_count, new_page = self.api._fetch_analyses_history(
            self.api, self._url, self.data)

        if not new_page:
            raise StopIteration()
        return self._update_current_page()

    def _update_current_page(self) -> List:
        """Update all metadata about new current page."""
        self._current_offset += len(self._current_page)
        self.pages.append(self._current_page)
        self._current_page_number = len(self.pages) - 1
        return self._current_page

    def __iter__(self):
        """Iterate for page."""
        yield from self._current_page
        self._fetch_page()
        if self._current_page:
            yield from iter(self)

    def previous_page(self) -> List:
        """Move to the previous page."""
        if self._current_page_number - 1 >= 0:
            self._current_page_number -= 1
            self._current_page = self.pages[self._current_page_number]
        return self._current_page

    def next_page(self) -> List:
        """Move to the next page"""
        if self._current_page_number == len(self.pages) - 1:
            return self._fetch_page()
        self._current_page_number += 1
        self._current_page = self.pages[self._current_page_number]
        return self._current_page

    @property
    def current_page(self) -> List:
        """Get current page, if not exits, ask a new one from server."""
        return self._current_page or self._fetch_page()

    def all(self) -> List:
        """Return all exits analysis's from server."""
        count_max_possible_rows = len(self.pages) * self._page_size
        while count_max_possible_rows < self.total_count:
            self._fetch_page()

        self._current_page_number = 0
        self._current_page = self.pages[0]

        all_pages = list(self)
        all_analysiss = []
        for page in all_pages:
            all_analysiss.extend(page)
        return all_analysiss
