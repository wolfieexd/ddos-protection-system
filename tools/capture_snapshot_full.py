#!/usr/bin/env python3
"""Capture a full-page screenshot of a server-rendered snapshot URL.
Usage: python tools/capture_snapshot_full.py --url URL --out screenshots/snapshot_full.png
"""
import time
import argparse
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager


def capture_full(url, out_path, width=1365):
    options = webdriver.ChromeOptions()
    options.add_argument('--headless=new')
    options.add_argument(f'--window-size={width},900')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    options.add_argument('--disable-gpu')

    service = Service(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=service, options=options)
    try:
        driver.get(url)
        time.sleep(0.5)
        # resize to full height
        height = driver.execute_script('return Math.max(document.body.scrollHeight, document.documentElement.scrollHeight);')
        driver.set_window_size(width, height + 50)
        time.sleep(0.3)
        png = driver.get_screenshot_as_png()
        with open(out_path, 'wb') as f:
            f.write(png)
        print('Saved full-page screenshot to', out_path)
    finally:
        driver.quit()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', required=True)
    parser.add_argument('--out', default='screenshots/snapshot_full.png')
    args = parser.parse_args()
    capture_full(args.url, args.out)
