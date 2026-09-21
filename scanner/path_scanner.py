import queue
import threading
import httpx
import uuid
from typing import Optional
from scanner.models import Finding
from scanner.rules import create_finding
from pathlib import Path


THREADS = 10
TIMEOUT = 5

BASE_DIR = Path(__file__).resolve().parent.parent

SENSITIVE_PATH_WORDLIST = (
    BASE_DIR / "wordlists" / "SENSITIVE_PATHS.txt"
)
OBJECT_PATH_WORDLIST = (
    BASE_DIR / "wordlists" / "OBJECT_PATHS.txt"
)

TESTWORDLIST = "wordlists/test.txt" ## FOR TESTING PURPOSES ONLY, NEED SHORT LIST TO MAKE TESTING FASTER, USED IN LINE 196 AND 205

LENGTH_TOLERANCE = 10


ERROR_PAGE_MARKERS = [
    "404 not found",
    "page not found",
    "resource not found",
    "requested page could not be found",
    "requested url was not found",
    "the page you are looking for does not exist"
]


def load_wordlist(file_name: str) -> queue.Queue:
    word_queue = queue.Queue()
    seen_paths = set()



    with open(file_name, "r") as file:
        for word in file:
            path = word.strip()

            if not path:
                continue

            if path in seen_paths:
                continue

            seen_paths.add(path)
            word_queue.put(path)

    return word_queue



def get_page_info(client: httpx.Client, url: str) -> dict :
    response = client.get(url, timeout = TIMEOUT, follow_redirects = False)

    return {
        "status_code" : response.status_code,
        "length" : len(response.content),
        "content-type": response.headers.get("content-type", "").lower(),
        "redirect_location": response.headers.get("location", ""),
        "body_sample": response.text[:500].lower(),
        "url" : url
    }

def contains_error_marker(page_info: dict) -> bool:
    body_sample = page_info["body_sample"]

    for marker in ERROR_PAGE_MARKERS:
        if marker in body_sample:
            return True

    return False

def get_error_base(base_url: str) -> Optional[dict]:
    fake_path = f"/domainguard-fake-error-{uuid.uuid4().hex}"
    fake_target_url = f"{base_url}{fake_path}"

    try:
        with httpx.Client() as client:
            baseline = get_page_info(client, fake_target_url)
 
            return baseline

    except httpx.HTTPError as error:
        print(f"[BASELINE ERROR] {error}")
        return None


def lengths_are_similar(length_error: int, length_test: int) -> bool :
    if length_error == 0 and length_test == 0:
        return True
    
    ceiling = max(length_error,length_test)
    floor = min(length_error, length_test)

    percentage_difference = (ceiling - floor) / ceiling * 100

    return percentage_difference <= LENGTH_TOLERANCE


def looks_like_error_page(page_info: dict, baseline: Optional[dict]) -> bool:

    if page_info["status_code"] in [404, 410]:
        return True
     
    if contains_error_marker(page_info):
        return True
    
    redirect_location = page_info["redirect_location"].lower()

    if any( 
        marker in redirect_location 
        for marker in ["/404", "/not-found", "/error"]
    ):
        return True
    
    similar_length = lengths_are_similar(
        page_info["length"],
        baseline["length"]
    )

    same_content_type = (
        page_info["content-type"]
        == baseline["content-type"]
    )

    if similar_length and same_content_type:
        return True

    return False

def worker(
    domain: str,
    word_queue: queue.Queue,
    findings: list[Finding],
    lock: threading.Lock,
    baseline: Optional[dict],
    protected_rule_id: str,
    accessible_rule_id: str
    ):

    with httpx.Client() as client:
        while True:
            try:
                path = word_queue.get_nowait()

            except queue.Empty:
                break

            try:
                url = f"{domain}{path}"
                page_info = get_page_info(client, url)
                status_code = page_info["status_code"]

                if status_code in [404,410]:
                    pass
                elif status_code in [401, 403]:
                    print(f"[/] Found but Protected: {url}")
                    finding = create_finding(
                        rule_id = protected_rule_id,
                        evidence=f"{url} returned HTTP {status_code}."
                    )
                    with lock:
                        findings.append(finding)

                elif status_code in [200, 206]:
                    if looks_like_error_page(page_info, baseline):
                        pass
                    else:
                        print(f"[+] Found: {url}")
                        finding = create_finding(
                            rule_id=accessible_rule_id, 
                            evidence=( 
                                "The response differed from the random error-page baseline and contained patterns associated with the requested file type. This is a probable exposure and requires manual verification. "
                                f"{url} returned HTTP {status_code}. "
                                f"Response length was {page_info['length']} bytes. "
                                f"Fake error page length was "
                                f"{baseline['length'] if baseline else 'unknown'} bytes."  
                                       )
                                    )
                        with lock:
                            findings.append(finding)
            except httpx.HTTPError:
                pass

            finally: 
                word_queue.task_done()



    
def _scan_paths(domain: str, word_list: str, protected_rule_id: str, accessible_rule_id: str) -> list[Finding]:
    word_queue = load_wordlist(word_list)
    threads = []
    findings = []
    lock = threading.Lock()


    baseline = get_error_base(domain)

    if not baseline:
        print("Could not create baseline error page")


    for _ in range(THREADS):
        thread = threading.Thread(
            target = worker, 
            args = (
                domain, 
                word_queue, 
                findings, 
                lock, 
                baseline,
                protected_rule_id,
                accessible_rule_id
                ))
        
        thread.start()
        threads.append(thread)

    word_queue.join()

    for thread in threads:
        thread.join()
    return findings
    
    
def scan_objects_paths(domain: str) -> list[Finding]:

    return _scan_paths(
        domain=domain,
        #word_list= OBJECT_PATH_WORDLIST,
        word_list=TESTWORDLIST, ## TEST WORDLIST FOR FASTER CHECKING ## ORIGINAL WORD LIST --> OBJECT_PATH_WORDLIST
        protected_rule_id="OBJ-002",
        accessible_rule_id="OBJ-001"
    )


def scan_path_exposure(domain: str) -> list[Finding]:
    return _scan_paths(
        domain=domain,
        #word_list=SENSITIVE_PATH_WORDLIST,
        word_list=TESTWORDLIST, ## TEST WORDLIST FOR FASTER CHECKING ## ORIGINAL WORD LIST --> SENSITIVE_PATH_WORDLIST
        protected_rule_id="PATH-002",
        accessible_rule_id="PATH-001"
    )