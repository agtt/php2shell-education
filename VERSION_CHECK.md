# PHP2Shell safe-version check

`check.php` verifies the patched PHP releases published for CVE-2026-109618 and CVE-2026-109619. When it can reach a verdict, it prints only `vulnerable` or `not vulnerable`, in English. It does not trigger the vulnerability and does not run an exploit.

Run it locally with the **same PHP installation** the web server uses:

```sh
php check.php
```

In Docker, you can run it via stdin without copying the file into the container:

```sh
docker exec -i CONTAINER_NAME php < check.php
```

For the optional, harmless HTTP probe, send a plain GET request to a PHP page on your own site:

```sh
php check.php https://example-my-site.com/index.php
```

This mode only checks the version in the `X-Powered-By: PHP/x.y.z` header of a successful response. It is also available via the `--url` option. If the server hides the header, adds a different layer, or the request does not reach PHP, it yields **no verdict** (exit code `2`); do not interpret this as "not vulnerable". The header version may not match the actual running PHP. For a more reliable result, use the local mode on the server. The HTTP probe does not dynamically confirm the existence of the vulnerability.

Exit code `1` means a vulnerable version, `0` means a patched version, and `2` means no verdict could be reached. The script runs only on the CLI; if accidentally opened via the web, it returns 404.

This is a **version check**, not a live exploitation test. `vulnerable` indicates that the upstream PHP version in use predates the fix; actual exploitability depends on the application and server configuration. `not vulnerable` indicates only that the relevant upstream fix release for these two CVEs has been reached. In custom builds where the distribution backports security patches under an older version number, the result may be a false positive; check your package vendor's security advisory. If you use a different CLI PHP installation than the server's PHP, the result applies to that installation.

Official sources: [CVE-2026-109618 advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w), [CVE-2026-109619 advisory](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp).
