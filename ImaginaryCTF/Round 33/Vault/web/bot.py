from playwright.sync_api import sync_playwright
import sys
import os
import time
import re

if __name__ == "__main__":
    url = sys.argv[1]
    target_url = sys.argv[2]
    flag = os.environ.get(
        "FLAG", "jctf{red_flags_and_fake_flags_form_an_equivalence_class}"
    )
    if not re.match(r"https?://", target_url):
        print("Invalid target url")
        exit(1)

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.goto(url)
        page.fill("#ta", flag)
        page.click("#btn")
        page.goto(target_url)
        time.sleep(5)
        browser.close()
