# virustotal

## Install

```console
$ pip install .
```

# Run

Basic usage pattern is:

```console
$ virustotal API_KEY FILENAME
```

Here `API_KEY` is the [VirusTotal API](https://www.virustotal.com/en/documentation/public-api/) key which you can register for free, and `FILENAME` is a path to the file you want to scan.

By default the tool first checks whether VirusTotal already has results for the file, and uploads it only when necessary. Setting the `--no-scan` option the file will not be sent.
