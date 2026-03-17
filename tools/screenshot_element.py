#!/usr/bin/env python3
"""Capture screenshot of a specific element (by CSS selector or ID).
Usage: python tools/screenshot_element.py --url URL --selector "#blockedTable" --out screenshots/blocked.png
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


def capture_element(url, selector, out_path, width=1365, height=768, timeout=15):
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
        try:
            WebDriverWait(driver, timeout).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, selector))
            )
        except Exception:
            time.sleep(2)

        el = driver.find_element(By.CSS_SELECTOR, selector)
        driver.execute_script('arguments[0].scrollIntoView({block:"center"});', el)
        time.sleep(1)

        # enlarge viewport if element is taller
        rect = driver.execute_script('return arguments[0].getBoundingClientRect();', el)
        height_needed = int(rect['height'] + 200)
        if height_needed > height:
            driver.set_window_size(width, height_needed)
            time.sleep(0.2)

        # take full page screenshot then crop using element location
        png = driver.get_screenshot_as_png()
        from PIL import Image
        import io
        img = Image.open(io.BytesIO(png))
        left = int(rect['left'])
        top = int(rect['top'])
        right = int(rect['right'])
        bottom = int(rect['bottom'])
        # expand bounds a bit
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
        print(f"Saved element screenshot to {out_path}")
    finally:
        driver.quit()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', required=True)
    parser.add_argument('--selector', required=True)
    parser.add_argument('--out', required=True)
    parser.add_argument('--width', type=int, default=1365)
    parser.add_argument('--height', type=int, default=768)
    parser.add_argument('--timeout', type=int, default=15)
    args = parser.parse_args()
    capture_element(args.url, args.selector, args.out, args.width, args.height, args.timeout)
