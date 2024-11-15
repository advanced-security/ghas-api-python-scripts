#!/usr/bin/env python3

"""Lightweight GitHub API client."""

import os
import re
import logging
import datetime
import time
import json
import traceback
import zoneinfo
from urllib.parse import urlunparse, urlencode, urlparse, parse_qs
from typing import Generator, Any
from collections import namedtuple
from tqdm import tqdm  # type: ignore
import requests  # type: ignore

LOG = logging.getLogger(__name__)

HOSTNAME_RE = re.compile(
    r"^([a-zA-Z0-9][a-zA-Z0-9-]{0,63})(\.([a-zA-Z0-9][a-zA-Z0-9-]{0,63}))*\.?$"
)
DAYS_AGO_RE = re.compile(r"^(?P<days>\d+)d$")
ISO_DATE_ONLY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
ISO_NO_TZ_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$")
VALID_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,39}$")


class RateLimited(Exception):
    """Rate limited exception."""
    pass


class GitHub:
    """A GitHub API client."""
    def __init__(self, token: str|None=None, hostname="github.com") -> None:
        token = token if token is not None else os.getenv("GITHUB_TOKEN")
        if token is None:
            raise ValueError("GITHUB_TOKEN environment variable must be set")

        self.session = requests.Session()
        self.session.headers.update({"Authorization": f"Bearer {token}"})
        self.session.headers.update({"Accept": "application/vnd.github.v3+json"})
        self.session.headers.update({"X-GitHub-Api-Version": "2022-11-28"})

        if not self.check_hostname(hostname):
            raise ValueError(
                "Invalid server hostname - use ASCII characters only, not IDNs; encode with punycode if necessary, and keep under 255 characters."
            )

        self.hostname = hostname

    @classmethod
    def check_name(self, name: str, scope:str) -> bool:
        """Check the name is valid."""
        # check repo slug has <owner</<repo> format or org/Enterprise name is valid
        if scope == "repo":
            if "/" not in name:
                return False
            owner, repo = name.split("/", 1)
            if not VALID_NAME_RE.match(owner) or not VALID_NAME_RE.match(repo):
                return False
        else:
            if not VALID_NAME_RE.match(name):
                return False
        return True

    @staticmethod
    def check_hostname(hostname: str) -> bool:
        """Check the hostname is valid."""
        if not HOSTNAME_RE.match(hostname):
            return False
        if len(hostname) > 255:
            return False
        return True

    @staticmethod
    def parse_link_header(link_header: str) -> dict:
        """Parse a Link header and return a dictionary of URLs."""
        links = {}
        for link in link_header.split(", "):
            url, rel = link.split("; ")
            url = url[1:-1]
            rel = rel[5:-1]
            links[rel] = url
        return links

    def query(self, scope: str, name: str, endpoint: str, query: dict|None=None, data: dict|None=None, method: str="GET", since: datetime.datetime|None=None, date_field:str="created_at", paging: None|str="cursor") -> Generator[dict, None, None]:
        """Query the GitHub API."""
        LOG.info(method)

        if method != "GET":
            paging = None

        url = self.construct_api_url(scope, name, endpoint, query, paging)
        
        if paging is None:
            try:
                result = self.do(url, method, data=data)
                yield result
            except Exception as e:
                LOG.error("Error: %s", e)
                # show traceback without raising the exception
                LOG.debug("".join(traceback.format_exception(e)))
        else:
            for result in self.paginate(url, since, date_field=date_field, cursor=paging == "cursor"):
                yield result

    def construct_api_url(self, scope: str, name: str, endpoint: str, query: dict|None, paging: None|str) -> str:
        """Construct the URL to query."""
        api_path = "/api/v3" if self.hostname != "github.com" else ""

        if scope == "repo":
            owner, repo = name.split("/", 1)
            scope_path = f"/repos/{requests.utils.quote(owner)}/{requests.utils.quote(repo)}"  # type: ignore
        elif scope == "org":
            scope_path = f"/orgs/{requests.utils.quote(name)}"  # type: ignore
        else:
            scope_path = f"/enterprises/{requests.utils.quote(name)}"  # type: ignore

        path = api_path + scope_path + endpoint

        if paging is None:
            query_params = {}
        elif paging == "cursor":
            query_params = {
                "per_page": 100,
                "before": ""
            }
        elif paging == "page":
            query_params = {
                "per_page": 100,
                "page": 1,
            }

        if query is not None:
            query_params.update(query)

        url = urlunparse(
            (
                'https',
                "api.github.com" if self.hostname == "github.com" else self.hostname,
                path,
                None,
                urlencode(query_params),
                None
            )
        )

        return url

    def get(self, url: str, query: dict|None=None, rate_limit: bool=True) -> requests.Response:
        """Do a single GET request, handle errors and rate limiting."""
        return self.do(url, "GET", query, rate_limit=rate_limit)

    def do(self, url, method="GET", query: dict|None=None, data: dict|None=None, rate_limit: bool=True) -> requests.Response:
        """Do a single request, handle errors and rate limiting."""
        if query is not None:
            parsed = urlparse(url)
            existing_query = parse_qs(parsed.query)
            existing_query.update(query)
            url = urlunparse(
                (
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    None,
                    urlencode(existing_query),
                    None,
                )
            )

        try:
            request = requests.Request(method, url, headers=self.session.headers, json=data)
            LOG.debug(request)
            response = self.session.send(request.prepare())
        except requests.ConnectionError as err:
            LOG.error("Connection error, stopping with what we have")
            raise err

        response.raise_for_status()

        LOG.debug("Response headers:")
        LOG.debug(json.dumps(dict(response.headers), indent=2))

        rate_limited = self._handle_rate_limit(response)
        if rate_limited:
            raise RateLimited()

        return response

    @staticmethod
    def _handle_rate_limit(response: requests.Response, apply_rate_limit: bool=True) -> bool:
        rate_limit_remaining = int(response.headers.get("X-RateLimit-Remaining", 0))
        rate_limit_reset = int(response.headers.get("X-RateLimit-Reset", 0))

        if rate_limit_remaining < 100:
            LOG.debug(
                f"Rate limit remaining: {rate_limit_remaining} until {datetime.datetime.fromtimestamp(rate_limit_reset)}"
            )
            if rate_limit_remaining == 0:
                rate_limit_reset = int(response.headers.get("X-RateLimit-Reset", 0))
                if rate_limit_reset != 0:
                    sleep_time = int(rate_limit_reset) - int(
                        datetime.datetime.utcnow().timestamp()
                    )
                    if sleep_time > 0:
                        LOG.debug(
                            f"Rate limit hit, sleeping for {sleep_time} seconds"
                        )
                        if apply_rate_limit:
                            time.sleep(sleep_time)
                            return True
            else:
                if apply_rate_limit:
                    time.sleep(5)

        retry_after = response.headers.get("Retry-After")
        if retry_after and apply_rate_limit:
            LOG.debug(f"Rate limit hit, retrying after {retry_after} seconds")
            time.sleep(int(retry_after))
            return True

        return False

    def paginate(self, url: str, since: datetime.datetime|None=None, date_field=str|None, progress: bool=True, cursor: bool=False) -> Generator[dict, None, None]:
        """Paginate the results of a GitHub API query."""

        if not cursor:
            raise NotImplementedError("Only cursor-based pagination is supported currently")
        
        if progress:
            pbar = tqdm(desc="GitHub API", unit=" requests")
            pbar.reset(total=None)

        while True:
            try:
                try:
                    response = self.get(url)
                except RateLimited:
                    continue
                except (requests.exceptions.HTTPError, requests.ConnectionError) as e:
                    LOG.error("HTTP error: %s, stopping with what we have", e)
                    break

                data = response.json()

                # If there are no more results, break out of the loop
                if isinstance(data, list) and len(data) == 0:
                    LOG.debug("No more results, stopping retrieval")
                    break

                if data is None or response is None:
                    break

                pbar.update(1)

                LOG.debug(data)

                # Append the results to the list
                for result in data:
                    yield result

                # Check if we have reached the end of the results by date range
                if since is not None and date_field is not None:
                    results_in_date_range = len(
                        [
                            item
                            for item in data
                            if date_field not in item or datetime.datetime.fromisoformat(item.get(date_field)) >= since
                        ]
                    )
                    if results_in_date_range == 0:
                        LOG.debug("No results left in date range, stopping retrieval")
                        break

                # Check if we have reached the end of the results by pagination
                link_header = response.headers.get("Link")
                if not link_header:
                    LOG.debug("No link header, stopping retrieval")
                    break
                links = self.parse_link_header(link_header)

                LOG.debug(links)

                if "next" not in links:
                    LOG.debug("No next link, stopping retrieval")
                    break

                url = links["next"]

            except KeyboardInterrupt:
                LOG.warning("Interrupted by user, stopping with what we have")
                break
            except Exception as e:
                LOG.error("Error: %s, stopping with what we have", e)
                # show traceback without raising the exception
                LOG.debug("".join(traceback.format_exception(e)))
                break

    def list_code_scanning_alerts(
        self, name: str, state: str|None = None, since: datetime.datetime|None = None, scope: str = "org"
    ) -> Generator[dict, None, None]:
        """List code scanning alerts for a GitHub repository, organization or Enterprise."""
        query = {"state": state} if state is not None else {}
        alerts = self.query(scope, name, "/code-scanning/alerts", query, since=since, date_field="created_at", paging="cursor")

        results = (
            alert for alert in alerts
            if (
                since is None
                or datetime.datetime.fromisoformat(alert["created_at"]) >= since
            )
        )

        return results
        
    def list_secret_scanning_alerts(
        self, name: str, state: str|None = None, since: datetime.datetime|None = None, scope: str = "org", bypassed: bool = False
    ) -> Generator[dict, None, None]:
        """List secret scanning alerts for a GitHub repository, organization or Enterprise."""
        query = {"state": state} if state is not None else {}
        alerts = self.query(scope, name, "/secret-scanning/alerts", query, since=since, date_field="created_at", paging="cursor")

        results = (
            alert for alert in alerts
            if (alert["push_protection_bypassed"] if bypassed else True) and
            (
                since is None
                or datetime.datetime.fromisoformat(alert["created_at"]) >= since
            )
        )

        return results


def parse_date(date: str) -> datetime.datetime | None:
    """Parse a date string and return a datetime object.

    Allow for a number of days ago, e.g. 7d for 7 days ago, and ISO dates.

    Add timezone info if it is missing.
    """
    if date is None:
        return None

    since = None

    if m := DAYS_AGO_RE.match(date):
        days = m.groupdict()["days"]
        since = datetime.datetime.utcnow() - datetime.timedelta(days=int(days))
    else:
        since_data = date
        if ISO_DATE_ONLY_RE.match(since_data):
            since_data += "T00:00:00Z"
        elif ISO_NO_TZ_RE.match(since_data):
            since_data += "Z"
        LOG.debug("Since: %s", since_data)
        try:
            since = datetime.datetime.fromisoformat(since_data)
        except ValueError:
            LOG.error(
                "Invalid since date/time - should be ISO 8601 format, e.g. 2024-10-08 or 2024-10-08T12:00:00Z"
            )
            return None
    if since is not None and since.tzinfo is None:
        LOG.debug("Added timezone info to since date/time")
        since = since.replace(tzinfo=zoneinfo.ZoneInfo("UTC"))
    return since
