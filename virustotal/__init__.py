import os
import json
import time
import click
import hashlib
import urlparse
import requests
import posixpath


VIRUSTOTAL_API_URL = "https://www.virustotal.com/vtapi/v2/"


class StatusCode(Exception):
    pass


class Forbidden(StatusCode):
    pass


class RateLimited(StatusCode):
    pass


def _request_wrapped(method, url, **kwargs):
    response = requests.request(method, url, **kwargs)

    if response.status_code == 403:
        raise Forbidden(response.status_code)
    elif response.status_code == 204:
        raise RateLimited(response.status_code)
    elif response.status_code != 200:
        raise StatusCode(response.status_code)

    return response.json()


class ResponseCode(Exception):
    pass


class UnknownResource(ResponseCode):
    pass


class WorkInProgress(ResponseCode):
    pass


def _check_response_code(response_code):
    if response_code == 0:
        raise UnknownResource(response_code)
    elif response_code == -2:
        raise WorkInProgress(response_code)
    elif response_code != 1:
        raise ResponseCode(response_code)


def _join_url_path(baseurl, path):
    """
    >>> _join_url_path("http://example.com/hello", "world")
    'http://example.com/hello/world'
    >>> _join_url_path("http://example.com/hello", "/world")
    'http://example.com/hello/world'
    >>> _join_url_path("http://example.com/hello", "../world")
    'http://example.com/hello/world'
    """

    path = posixpath.normpath(posixpath.join("/", path))
    parsed = list(urlparse.urlparse(baseurl))
    parsed[2] = posixpath.normpath(posixpath.join(parsed[2], "." + path))
    return urlparse.urlunparse(parsed)


def _hash_file(fileobj, hash_type=hashlib.sha256):
    hasher = hash_type()

    offset = fileobj.tell()
    try:
        while True:
            data = fileobj.read(1024 ** 2)
            if not data:
                break
            hasher.update(data)
    finally:
        fileobj.seek(offset)

    return hasher.hexdigest()


class VirusTotal(object):
    def __init__(self, api_key, api_url=VIRUSTOTAL_API_URL, retry_interval=15.0):
        self._api_key = api_key
        self._api_url = api_url
        self._retry_interval = retry_interval

    def _url(self, path):
        return _join_url_path(self._api_url, path)

    def report(self, resource):
        while True:
            try:
                result = _request_wrapped(
                    "POST",
                    self._url("file/report"),
                    data={
                        "apikey": self._api_key,
                        "resource": resource
                    }
                )
                _check_response_code(result["response_code"])
            except (WorkInProgress, RateLimited):
                time.sleep(self._retry_interval)
            else:
                return result

    def behaviour(self, filehash):
        while True:
            try:
                result = _request_wrapped(
                    "GET",
                    self._url("file/behaviour"),
                    params={
                        "apikey": self._api_key,
                        "hash": filehash
                    }
                )
                if "response_code" in result:
                    _check_response_code(result["response_code"])
            except (WorkInProgress, RateLimited):
                time.sleep(self._retry_interval)
            else:
                return result

    def network_traffic(self, filehash):
        while True:
            try:
                result = _request_wrapped(
                    "GET",
                    self._url("file/network-traffic"),
                    params={
                        "apikey": self._api_key,
                        "hash": filehash
                    }
                )
                if "response_code" in result:
                    _check_response_code(result["response_code"])
            except (WorkInProgress, RateLimited):
                time.sleep(self._retry_interval)
            else:
                return result

    def scan(self, fileobj, filename=None):
        basename = os.path.basename(filename)

        while True:
            try:
                result = _request_wrapped(
                    "POST",
                    self._url("file/scan"),
                    data={
                        "apikey": self._api_key
                    },
                    files=[
                        ("file", (basename, fileobj))
                    ]
                )
                _check_response_code(result["response_code"])
            except RateLimited:
                time.sleep(self._retry_interval)
            else:
                return self.report(result["scan_id"])


@click.command()
@click.argument("api-key")
@click.argument("filename", type=click.Path(exists=True))
@click.option("--scan/--no-scan", default=True)
@click.option("--api-url", default=VIRUSTOTAL_API_URL)
@click.option("--retry-interval", type=click.FLOAT, default=5.0)
def main(api_key, filename, scan, api_url, retry_interval):
    vt = VirusTotal(api_key, api_url=api_url, retry_interval=retry_interval)

    with open(filename, "rb") as fileobj:
        filehash = _hash_file(fileobj)
        try:
            report = vt.report(filehash)
        except UnknownResource:
            if scan:
                report = vt.scan(fileobj, filename=filename)
            else:
                report = None

    result = {}

    if report is not None:
        result["report"] = report

        try:
            result["behaviour"] = vt.behaviour(filehash)
        except (UnknownResource, Forbidden):
            pass

        try:
            result["network-traffic"] = vt.network_traffic(filehash)
        except (UnknownResource, Forbidden):
            pass

    print json.dumps(result, indent=2)


if __name__ == "__main__":
    main()
