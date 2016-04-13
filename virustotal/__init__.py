import os
import json
import time
import click
import hashlib
import urlparse
import requests
import posixpath


VIRUSTOTAL_API_URL = "https://www.virustotal.com/vtapi/v2/"


class UnknownResponseCode(Exception):
    pass


class UnknownResource(Exception):
    pass


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
            response = requests.post(
                self._url("file/report"),
                data={
                    "apikey": self._api_key,
                    "resource": resource
                }
            )

            if response.status_code != 204:
                response.raise_for_status()
                report = response.json()

                response_code = report["response_code"]
                if response_code == 1:
                    return report

                if response_code == 0:
                    raise UnknownResource()
                elif response_code != -2:
                    raise UnknownResponseCode(response_code, report["verbose_msg"])
            time.sleep(self._retry_interval)

    def scan_file(self, fileobj, filename=None):
        basename = os.path.basename(filename)

        while True:
            response = requests.post(
                self._url("file/scan"),
                data={
                    "apikey": self._api_key
                },
                files=[
                    ("file", (basename, fileobj))
                ]
            )

            if response.status_code == 204:
                time.sleep(self._retry_interval)
                continue

            response.raise_for_status()
            report = response.json()

            response_code = report["response_code"]
            if response_code != 1:
                raise UnknownResponseCode(response_code, report["verbose_msg"])

            return self.report(report["scan_id"])


@click.command()
@click.argument("api-key")
@click.argument("filename", type=click.Path(exists=True))
@click.option("--api-url", default=VIRUSTOTAL_API_URL)
@click.option("--retry-interval", type=click.FLOAT, default=5.0)
def main(api_key, filename, api_url, retry_interval):
    vt = VirusTotal(api_key, api_url=api_url, retry_interval=retry_interval)

    with open(filename, "rb") as fileobj:
        try:
            report = vt.report(_hash_file(fileobj))
        except UnknownResource:
            report = vt.scan(fileobj, filename=filename)

    print json.dumps(report, indent=2)


if __name__ == "__main__":
    main()
