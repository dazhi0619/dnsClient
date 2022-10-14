# A Simple DNS Client

This is an assignment of course CS305 in SUSTech. It was not required to manually construct DNS queries and parse responses, but I found it rather interesting and this could familiarize myself with network programming in Python, so I spent a little more time to write it.

## Features

1. Support DNS queries and responses of type A, AAAA, NS, MX, CNAME.
2. Formatted output as default.
3. Flexible: To support other DNS query types, simply modify the QueryType enum class and RecordData class. To customize the output, you will find the attributes easy to format.
4. Support demonstrating the process of iterative queries, like `dig +trace`

## Known problems

1. Because SOA, OPT messages are not supported, exceptions may occur when querying specific domains, for example, [news.apple](https://news.apple).

## Usage

```sh
'dnsclient.py --domain <domain> [--type <type>] [--dns <dns>] [--iterative]'
```