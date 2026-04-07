from PIL import Image, ImageDraw, ImageFont
import os

WIDTH, HEIGHT = 1440, 800
BG = (24, 32, 46)
CARD_BG = (26, 35, 50)
TEXT = (224, 224, 224)
BLUE = (0, 212, 255)
RED = (255, 23, 68)
ORANGE = (255, 145, 0)
GREEN = (0, 200, 83)

font_path = os.path.join(os.path.dirname(__file__), 'arial.ttf')
try:
    font_title = ImageFont.truetype(font_path, 32)
    font_label = ImageFont.truetype(font_path, 18)
    font_value = ImageFont.truetype(font_path, 28)
    font_small = ImageFont.truetype(font_path, 14)
except:
    font_title = font_label = font_value = font_small = ImageFont.load_default()

img = Image.new('RGB', (WIDTH, HEIGHT), BG)
draw = ImageDraw.Draw(img)

def card(x, y, w, h):
    draw.rectangle([x, y, x+w, y+h], fill=CARD_BG, outline=(42, 58, 74))

# Header
draw.text((40, 30), 'DDoS Protection Dashboard', font=font_title, fill=BLUE)
draw.text((WIDTH-180, 40), 'LIVE', font=font_label, fill=GREEN)
draw.text((WIDTH-110, 40), 'HEALTHY', font=font_label, fill=GREEN)

# Cards
card(40, 90, 320, 90)
card(380, 90, 320, 90)
card(720, 90, 320, 90)
card(1060, 90, 320, 90)

draw.text((60, 110), 'TOTAL REQUESTS', font=font_label, fill=TEXT)
draw.text((60, 140), '2,350', font=font_value, fill=BLUE)
draw.text((400, 110), 'ATTACKS DETECTED', font=font_label, fill=TEXT)
draw.text((400, 140), '17', font=font_value, fill=RED)
draw.text((740, 110), 'IPS BLOCKED', font=font_label, fill=TEXT)
draw.text((740, 140), '5', font=font_value, fill=ORANGE)
draw.text((1080, 110), 'SYSTEM UPTIME', font=font_label, fill=TEXT)
draw.text((1080, 140), '2h 14m', font=font_value, fill=GREEN)

# Traffic chart placeholder
card(40, 200, 660, 180)
draw.text((60, 220), 'TRAFFIC OVER TIME', font=font_label, fill=TEXT)
draw.line([(80, 260), (200, 320), (320, 240), (440, 340), (560, 220), (640, 320)], fill=BLUE, width=4)

# Attack types chart placeholder
card(720, 200, 660, 180)
draw.text((740, 220), 'ATTACK TYPES', font=font_label, fill=TEXT)
draw.pieslice([900, 260, 1100, 460], 0, 120, fill=RED)
draw.pieslice([900, 260, 1100, 460], 120, 240, fill=ORANGE)
draw.pieslice([900, 260, 1100, 460], 240, 360, fill=GREEN)
draw.text((1120, 320), 'IP Flooding', font=font_small, fill=RED)
draw.text((1120, 350), 'Distributed', font=font_small, fill=ORANGE)
draw.text((1120, 380), 'Behavioral', font=font_small, fill=GREEN)

# Blocked IPs table
card(40, 400, 660, 120)
draw.text((60, 420), 'BLOCKED IPS', font=font_label, fill=TEXT)
ips = ['172.18.0.1', '192.168.1.100', '10.0.0.5', '172.18.0.3', '203.0.113.45']
for i, ip in enumerate(ips):
    draw.text((60, 450+i*20), ip, font=font_small, fill=TEXT)

# Recent Attacks table
card(720, 400, 660, 120)
draw.text((740, 420), 'RECENT ATTACKS', font=font_label, fill=TEXT)
attacks = [
    ('19:12:38', 'IP_FLOODING', '172.18.0.1', 'HIGH'),
    ('19:13:36', 'DDOS_DISTRIBUTED', '192.168.1.100', 'CRITICAL'),
    ('19:14:21', 'BEHAVIORAL_BLOCK', '10.0.0.5', 'CRITICAL'),
    ('19:15:02', 'IP_FLOODING', '203.0.113.45', 'HIGH'),
    ('19:16:44', 'IP_FLOODING', '172.18.0.3', 'HIGH'),
]
for i, (t, typ, ip, sev) in enumerate(attacks):
    draw.text((740, 450+i*20), f'{t} {typ} {ip} {sev}', font=font_small, fill=TEXT)

img.save('screenshots/dashboard_sample_data.png')
print('Generated dashboard_sample_data.png')
