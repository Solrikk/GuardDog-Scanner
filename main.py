import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor
import re

COMMON_PATHS = [
    "admin/", "login/", "admin/login.php", "admin/index.php", "administrator/",
    "config.php", "backup/", "backup.zip", ".git/", ".env", "db.sql"
]

SECURITY_HEADERS = [
    "Content-Security-Policy", "Strict-Transport-Security",
    "X-Content-Type-Options", "X-Frame-Options", "X-XSS-Protection",
    "Referrer-Policy", "Permissions-Policy"
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>", "\"><script>alert('XSS')</script>"
]


def scan_vulnerable_paths(base_url):
  vulnerabilities = []

  def check_path(path):
    url = base_url + path
    try:
      response = requests.get(url, timeout=5)
      if response.status_code == 200:
        vulnerabilities.append(url)
    except requests.RequestException:
      pass

  with ThreadPoolExecutor(max_workers=10) as executor:
    executor.map(check_path, COMMON_PATHS)

  return vulnerabilities


def check_security_headers(base_url):
  response = requests.get(base_url)
  missing_headers = [
      header for header in SECURITY_HEADERS if header not in response.headers
  ]
  return missing_headers


def scan_forms(base_url):
  form_vulnerabilities = []

  try:
    response = requests.get(base_url, timeout=5)
    soup = BeautifulSoup(response.text, 'html.parser')
    forms = soup.find_all("form")

    for form in forms:
      action = form.get("action")
      method = form.get("method", "get").lower()
      if action:
        form_url = urljoin(base_url, action)
        sql_vulnerable = check_sql_injection_vulnerability(form_url, method)
        xss_vulnerable = check_xss_vulnerability(form_url, method)
        form_vulnerabilities.append((form_url, sql_vulnerable, xss_vulnerable))
  except requests.RequestException:
    pass

  return form_vulnerabilities


def check_sql_injection_vulnerability(url, method):
  payloads = [
      "' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1' /*", "` OR '1'='1",
      "' OR 1=1--"
  ]
  vulnerable = False

  for payload in payloads:
    if method == "post":
      response = requests.post(url, data={"param": payload}, timeout=5)
    else:
      response = requests.get(url, params={"param": payload}, timeout=5)

    if "error" in response.text.lower() or "sql" in response.text.lower():
      vulnerable = True
      break

  return vulnerable


def check_xss_vulnerability(url, method):
  vulnerable = False

  for payload in XSS_PAYLOADS:
    if method == "post":
      response = requests.post(url, data={"param": payload}, timeout=5)
    else:
      response = requests.get(url, params={"param": payload}, timeout=5)

    if payload in response.text:
      vulnerable = True
      break

  return vulnerable


def crawl_site(base_url):
  visited = set()
  to_visit = {base_url}
  found_links = []

  while to_visit:
    url = to_visit.pop()
    if url in visited:
      continue

    try:
      response = requests.get(url, timeout=5)
      visited.add(url)
      soup = BeautifulSoup(response.text, 'html.parser')
      found_links.append(url)

      for link in soup.find_all("a"):
        href = link.get("href")
        if href:
          full_url = urljoin(base_url, href)
          if base_url in full_url and full_url not in visited:
            to_visit.add(full_url)
    except requests.RequestException:
      continue

  return found_links


def check_cookies(base_url):
  response = requests.get(base_url)
  cookies = response.cookies
  not_secure = [cookie.name for cookie in cookies if not cookie.secure]
  not_http_only = [
      cookie.name for cookie in cookies
      if not cookie.has_nonstandard_attr('HttpOnly')
  ]
  return not_secure, not_http_only


def validate_url(url):
  parsed = urlparse(url)
  return all([parsed.scheme, parsed.netloc])


def main():
  base_url = input("Enter the base URL to scan: ").strip().rstrip('/') + '/'

  if not validate_url(base_url):
    print("Invalid URL format. Please enter a valid URL.")
    return

  vulnerabilities = scan_vulnerable_paths(base_url)
  missing_headers = check_security_headers(base_url)
  form_vulnerabilities = scan_forms(base_url)
  links = crawl_site(base_url)
  not_secure_cookies, not_http_only_cookies = check_cookies(base_url)

  print_report(base_url, vulnerabilities, missing_headers,
               form_vulnerabilities, links, not_secure_cookies,
               not_http_only_cookies)


def print_report(base_url, vulnerabilities, missing_headers,
                 form_vulnerabilities, links, not_secure_cookies,
                 not_http_only_cookies):
  print(f"Security Scan Report for: {base_url}\n")

  print("1. Vulnerable Paths:")
  if vulnerabilities:
    print("Found the following vulnerable paths:")
    for vuln in vulnerabilities:
      print(f"- {vuln}")
  else:
    print("No common vulnerabilities found.")
  print()

  print("2. Missing Security Headers:")
  if missing_headers:
    print("The following security headers are missing:")
    for header in missing_headers:
      print(f"- {header}")
    print(
        "Recommended Actions: Ensure the missing headers are configured correctly on your web server to enhance security."
    )
  else:
    print("All security headers are present.")
  print()

  print("3. Forms Vulnerabilities:")
  if form_vulnerabilities:
    print("Found web forms with the following URLs and vulnerabilities:")
    for form_url, sql_vuln, xss_vuln in form_vulnerabilities:
      print(f"- {form_url}:")
      print(f"  - SQL Injection Vulnerable: {'Yes' if sql_vuln else 'No'}")
      print(f"  - XSS Vulnerable: {'Yes' if xss_vuln else 'No'}")
  else:
    print(
        "No web forms found on the main page or no vulnerabilities detected.")
  print()

  print("4. Internal Links:")
  if links:
    print("Found the following internal links:")
    for link in links:
      print(f"- {link}")
  else:
    print("No internal links found.")
  print()

  print("5. Cookie Security Issues:")
  if not_secure_cookies or not_http_only_cookies:
    if not_secure_cookies:
      print("The following cookies are not marked Secure:")
      for cookie in not_secure_cookies:
        print(f"- {cookie}")
    if not_http_only_cookies:
      print("The following cookies are not marked HttpOnly:")
      for cookie in not_http_only_cookies:
        print(f"- {cookie}")
    print(
        "Recommended Actions: Ensure cookies are marked as Secure and HttpOnly to protect them from being accessed through client-side scripts."
    )
  else:
    print("All cookies are secure.")
  print()


if __name__ == "__main__":
  main()
