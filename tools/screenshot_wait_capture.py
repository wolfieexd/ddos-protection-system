#!/usr/bin/env python3
"""Wait for dashboard to populate (non-zero stats or table rows) then capture elements.
Usage: python tools/screenshot_wait_capture.py --url URL --out_dir screenshots --timeout 30
"""
import time
import argparse
import os
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from webdriver_manager.chrome import ChromeDriverManager


def wait_for_data(driver, timeout=30):
    start = time.time()
    while time.time() - start < timeout:
        try:
            total = driver.execute_script("return document.getElementById('totalRequests') && document.getElementById('totalRequests').textContent.trim();")
            blocked_count = driver.execute_script("var tb=document.getElementById('blockedTable'); if(!tb) return 0; return tb.children.length;")
            attacks_count = driver.execute_script("var tb=document.getElementById('attacksTable'); if(!tb) return 0; return tb.children.length;")
            if total and total!='0':
                return True
            if blocked_count and int(blocked_count)>0:
                return True
            if attacks_count and int(attacks_count)>0:
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


def capture_element_crop(driver, selector, out_path):
    el = driver.find_element(By.CSS_SELECTOR, selector)
    driver.execute_script('arguments[0].scrollIntoView({block:"center"});', el)
    time.sleep(0.5)
    rect = driver.execute_script('return arguments[0].getBoundingClientRect();', el)
    png = driver.get_screenshot_as_png()
    from PIL import Image
    import io
    img = Image.open(io.BytesIO(png))
    left = int(rect['left'])
    top = int(rect['top'])
    right = int(rect['right'])
    bottom = int(rect['bottom'])
    pad = 20
    left = max(0, left-pad)
    top = max(0, top-pad)
    right = min(img.width, right+pad)
    bottom = min(img.height, bottom+pad)
    cropped = img.crop((left, top, right, bottom))
    out_dir = os.path.dirname(out_path)
    if out_dir and not os.path.exists(out_dir):
        os.makedirs(out_dir, exist_ok=True)
    cropped.save(out_path)


def main(url, out_dir, timeout=30, width=1365, height=900):
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
        ok = wait_for_data(driver, timeout=timeout)
        if not ok:
            print('Timeout waiting for dashboard data; proceeding to capture anyway.')
        # capture three elements
        capture_element_crop(driver, '#blockedTable', os.path.join(out_dir, 'blocked_ips_final.png'))
        capture_element_crop(driver, '#attacksTable', os.path.join(out_dir, 'recent_attacks_final.png'))
        capture_element_crop(driver, '#trafficChart', os.path.join(out_dir, 'traffic_chart_final.png'))
        print('Saved final screenshots in', out_dir)
    finally:
        driver.quit()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', required=True)
    parser.add_argument('--out_dir', default='screenshots')
    parser.add_argument('--timeout', type=int, default=30)
    parser.add_argument('--width', type=int, default=1365)
    parser.add_argument('--height', type=int, default=900)
    args = parser.parse_args()
    main(args.url, args.out_dir, args.timeout, args.width, args.height)
