# Windows account-isolation setup

This preset is for ten long-lived account profiles on one Windows machine,
with no more than five open at once.

## Proxy choice and format

Use authenticated SOCKS5 with a fixed or provider-sticky exit. SOCKS5 carries
the destination hostname to the proxy, and PiBrowse's per-profile relay always
uses remote-resolution semantics. Do not use SOCKS4. Do not buy a plan that
rotates the exit on every request for a long-lived account.

The import format is the common proxy URI form:

```text
socks5://username:password@host:port
```

PiBrowse also accepts `socks5h://`; it normalises both forms to the same remote
DNS behaviour. The proxy importer accepts one URI per line. The CSV profile
importer accepts the same URI in its `proxy` column.

Templates for ten accounts are in:

- `examples/windows-account-isolation/proxies.txt`
- `examples/windows-account-isolation/profiles.csv`

Replace every example host, username and password before importing. Leave the
timezone and languages cells empty: launch then derives both, plus geolocation,
from the checked proxy exit instead of pinning a contradictory value.

## Enforced policy

On first agent start PiBrowse writes `%APPDATA%\Fury\isolation.json`:

```json
{
  "strict": true,
  "max_concurrent_profiles": 5,
  "require_proxy": true,
  "check_exit_on_every_launch": true,
  "unique_proxy_per_profile": true,
  "unique_exit_ip": true
}
```

Strict launch does all of the following before Chromium starts:

1. requires a proxy even when the profile previously allowed direct access;
2. resolves the actual exit through that proxy on every launch;
3. refuses an invalid or unavailable exit check (fail closed);
4. reserves both the proxy id and observed public IP to one profile;
5. refuses a second profile even when different credentials share one gateway;
6. limits running and currently-launching profiles together to five;
7. requires a Windows persona on Windows and per-profile canvas noise.

The assignment survives restarts in the local SQLite database. Purging a
profile from Trash releases its assignment; merely closing or soft-deleting it
does not, so an aged account cannot accidentally lose its network identity.

## Provider requirements

For each of the ten proxies record:

- protocol, host and port;
- username and password, or the Windows machine IP authorised by the provider;
- advertised country/city and ISP/ASN type;
- whether the session is static or sticky, and its expiry;
- whether IPv6 is supported;
- a provider rotation URL only if rotations are deliberate.

Ten credentials are not enough by themselves. Check all ten in PiBrowse: every
row must report a different `last_ip`. The strict launch check is the final
backstop because providers can change or consolidate exits after purchase.

## Remaining boundary

This prevents browser profiles from sharing storage, proxy credentials,
observable exit IP and the same per-profile noise seed. It cannot make account
identity independent when the service sees reused phone numbers, recovery
mailboxes, payment instruments, names, uploaded files or identical automated
behaviour. Those must also stay separated operationally.
