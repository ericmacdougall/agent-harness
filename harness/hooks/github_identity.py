"""Credential-free repository identities for supported github.com Git URLs."""

import re
from urllib.parse import urlsplit


def _text(value):
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise ValueError('Unsupported GitHub repository identity')
    try:
        value.encode('utf-8')
    except UnicodeError:
        raise ValueError('Unsupported GitHub repository identity') from None
    # urlsplit normalizes some control characters. Refuse them before parsing.
    if any(ord(char) <= 32 or ord(char) == 127 for char in value):
        raise ValueError('Unsupported GitHub repository identity')
    return value


def repository_name(value):
    """Validate an OWNER/REPO argument without interpreting URL syntax."""
    value = _text(value)
    parts = value.split('/')
    if len(parts) != 2:
        raise ValueError('Unsupported GitHub repository identity')
    owner, repo = parts
    # Underscore also supports managed-account short codes. This validates
    # bounded path syntax, not account existence or authorization.
    if (not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9_-]{0,37}[A-Za-z0-9])?', owner)
            or not re.fullmatch(r'[A-Za-z0-9_.-]{1,100}', repo)
            or repo in {'.', '..'}):
        raise ValueError('Unsupported GitHub repository identity')
    return (owner + '/' + repo).lower()


def github_repository(url):
    """Return the lowercase OWNER/REPO for a standard GitHub Git URL.

    HTTPS and SSH default ports are accepted. Embedded credentials, alternate
    hosts, query/fragment syntax and encoded path aliases are unsupported.
    This function never contacts a remote or returns the original URL in errors.
    """
    url = _text(url)
    if '?' in url or '#' in url:
        raise ValueError('Unsupported GitHub repository identity')
    scp = re.fullmatch(r'git@([^:]+):(.+)', url)
    if scp:
        if scp.group(1).lower() != 'github.com':
            raise ValueError('Unsupported GitHub repository identity')
        path = scp.group(2)
    else:
        try:
            parsed = urlsplit(url)
            port = parsed.port
            if parsed.hostname != 'github.com' or parsed.password is not None:
                raise ValueError('Unsupported GitHub repository identity')
            if parsed.scheme == 'https':
                if parsed.username is not None or port not in (None, 443):
                    raise ValueError('Unsupported GitHub repository identity')
            elif parsed.scheme == 'ssh':
                if parsed.username != 'git' or port not in (None, 22):
                    raise ValueError('Unsupported GitHub repository identity')
            else:
                raise ValueError('Unsupported GitHub repository identity')
            if not parsed.path.startswith('/'):
                raise ValueError('Unsupported GitHub repository identity')
            path = parsed.path[1:]
        except ValueError:
            raise ValueError('Unsupported GitHub repository identity') from None
    path = path.removesuffix('/').removesuffix('.git')
    return repository_name(path)
