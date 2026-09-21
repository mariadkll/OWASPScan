import queue
import threading

import httpx

from scanner.models import Finding
from scanner.rules import create_finding


TIMEOUT = 5
DEFAULT_REQUEST_COUNT = 10
THREADS = 10

RATE_LIMIT_HEADERS = [
    "ratelimit-limit",
    "ratelimit-remaining",
    "ratelimit-reset",
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "retry-after"
]


def get_rate_limit_headers(headers: httpx.Headers) -> dict:
    found_headers = {}

    for header_name in RATE_LIMIT_HEADERS:
        header_value = headers.get(header_name)

        if header_value:
            found_headers[header_name] = header_value

    return found_headers


def check_rate_limit_headers(domain: str) -> list[Finding]:
    findings = []
    url = f"{domain.rstrip('/')}/"

    try:
        with httpx.Client(
            timeout=TIMEOUT,
            follow_redirects=True
        ) as client:
            response = client.get(url)

        rate_limit_headers = get_rate_limit_headers(response.headers)

        if not rate_limit_headers:
            findings.append(
                create_finding(
                    rule_id="RATE-001",
                    evidence=(
                        f"Tested URL: {url}. "
                        "No visible rate-limit headers were found in the response. "
                        f"The URL returned HTTP {response.status_code}. "
                        f"Checked headers: {RATE_LIMIT_HEADERS}. "
                        "This does not confirm that rate limiting is absent."
                    )
                )
            )

    except httpx.HTTPError as error:
        findings.append(
            create_finding(
                rule_id="RATE-005",
                evidence=(
                    f"Tested URL: {url}. "
                    f"Could not inspect rate-limit headers: {error}."
                )
            )
        )

    return findings


def worker(
    target: str,
    request_queue: queue.Queue,
    rate_limit_headers: dict,
    status_codes: list[int],
    lock: threading.Lock,
    errors: list[str]
) -> None:

    with httpx.Client(
        timeout=TIMEOUT,
        follow_redirects=True
    ) as client:

        while True:
            try:
                request_queue.get_nowait()

            except queue.Empty:
                break

            try:
                response = client.get(target)

                found_headers = get_rate_limit_headers(
                    response.headers
                )

                with lock:
                    status_codes.append(response.status_code)
                    rate_limit_headers.update(found_headers)

            except httpx.HTTPError as error:
                with lock:
                    errors.append(str(error))

            finally:
                request_queue.task_done()


def check_rate_limit_behavior(
    domain: str,
    path: str = "/",
    request_count: int = DEFAULT_REQUEST_COUNT
) -> list[Finding]:

    findings = []

    target = f"{domain.rstrip('/')}/{path.lstrip('/')}"

    request_queue = queue.Queue()
    status_codes = []
    rate_limit_headers = {}
    errors = []
    threads = []
    lock = threading.Lock()


    for _ in range(request_count):
        request_queue.put(None)


    thread_count = min(
    THREADS,
    request_count
    )

    for _ in range(thread_count):
        thread = threading.Thread(
            target=worker,
            args=(
                target,
                request_queue,
                rate_limit_headers,
                status_codes,
                lock,
                errors
            )
        )

        thread.start()
        threads.append(thread)

    request_queue.join()

    for thread in threads:
        thread.join()


    if not status_codes:
        findings.append(
            create_finding(
                rule_id="RATE-005",
                evidence=(
                    f"Tested URL: {target}. "
                    "The concurrent rate-limit test could not receive "
                    f"any responses. Errors: {errors}."
                )
            )
        )

        return findings


    if 429 in status_codes:
        findings.append(
            create_finding(
                rule_id="RATE-003",
                evidence=(
                    f"Tested URL: {target}. "
                    "The application returned HTTP 429 Too Many Requests "
                    "during the concurrent request test. "
                    f"Request count: {request_count}. "
                    f"Status codes: {status_codes}. "
                    f"Rate-limit headers: {rate_limit_headers}."
                )
            )
        )

        return findings

    # Check for repeated blocking or authorization responses.
    forbidden_requests = 0

    for status_code in status_codes:
        if status_code in [401, 403]:
            forbidden_requests += 1

    if forbidden_requests >= 3:
        findings.append(
            create_finding(
                rule_id="RATE-004",
                evidence=(
                    f"Tested URL: {target}. "
                    f"{forbidden_requests} requests returned HTTP 401 or 403. "
                    f"Status codes: {status_codes}. "
                    "This may indicate authentication protection, WAF behavior, "
                    "or scanner blocking."
                )
            )
        )

        return findings

    # Count successful responses.
    successful_requests = 0

    for status_code in status_codes:
        if 200 <= status_code < 400:
            successful_requests += 1

    # All requests succeeded without visible rate-limit behavior.
    if (
        successful_requests == request_count
        and not rate_limit_headers
    ):
        findings.append(
            create_finding(
                rule_id="RATE-002",
                evidence=(
                    f"Tested URL: {target}. "
                    f"The application accepted {request_count} concurrent requests "
                    "without returning HTTP 429 or visible rate-limit headers. "
                    f"Status codes: {status_codes}. "
                    "This does not confirm that rate limiting is absent."
                )
            )
        )

    return findings


def check_rate_limiting(domain: str) -> list[Finding]:
    findings = []

    findings.extend(
        check_rate_limit_headers(domain)
    )

    findings.extend(
        check_rate_limit_behavior(
            domain=domain,
            path="/",
            request_count=DEFAULT_REQUEST_COUNT
        )
    )

    return findings