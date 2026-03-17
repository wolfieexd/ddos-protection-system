#!/usr/bin/env python3
"""Headless dashboard screenshot tool.
Usage: python tools/screenshot_dashboard.py --url URL --out path
"""
import time
import argparse
import os
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager


def capture(url, out_path, width=1365, height=768, timeout=15):
    options = webdriver.ChromeOptions()
    options.add_argument('--headless=new')
    options.add_argument(f'--window-size={width},{height}')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    options.add_argument('--disable-gpu')

    service = Service(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=service, options=options)
    try:
        driver.get(url)
        # Wait for main elements to load or timeout
        try:
            WebDriverWait(driver, timeout).until(
                EC.presence_of_element_located((By.ID, 'totalRequests'))
            )
        except Exception:
            # fallback wait
            time.sleep(3)

        # give charts some time to render
        time.sleep(1)

        out_dir = os.path.dirname(out_path)
        if out_dir and not os.path.exists(out_dir):
            os.makedirs(out_dir, exist_ok=True)

        driver.save_screenshot(out_path)
        print(f"Saved screenshot to {out_path}")
    finally:
        driver.quit()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', required=True, help='Dashboard URL')
    parser.add_argument('--out', required=True, help='Output PNG path')
    parser.add_argument('--width', type=int, default=1365)
    parser.add_argument('--height', type=int, default=768)
    parser.add_argument('--timeout', type=int, default=15)
    args = parser.parse_args()
    capture(args.url, args.out, args.width, args.height, args.timeout)
