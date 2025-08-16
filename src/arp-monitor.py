#!/usr/bin/env python3
import sys
sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

import os
import time
import json
from scapy.all import sniff, ARP
from datetime import datetime, timedelta
import requests
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
import signal

# === Paths ===
CONFIG_FILE = "/etc/arp-monitor/config.json"
OUI_FILE = "/var/lib/arp-monitor/oui.txt"
STATE_FILE = "/var/lib/arp-monitor/state.json"
FAVICON_FILE = "/opt/arp-monitor/arpmon.png"
CSS_FILE = "/opt/arp-monitor/style.css"

# === Load Config ===
with open(CONFIG_FILE) as f:
  cfg = json.load(f)

TELEGRAM_ENABLED = cfg.get("telegramEnabled", False)
BOT_TOKEN = cfg.get("telegramBotToken") if TELEGRAM_ENABLED else None
CHAT_ID = cfg.get("telegramChatId") if TELEGRAM_ENABLED else None
ENTRY_TIMEOUT = timedelta(hours=cfg.get("entryTimeoutHours", 24))
ALERT_COOLDOWN = cfg.get("alertCooldownSeconds", 300)
HTTP_PORT = cfg.get("httpPort", 8080)
HTTP_LOG_LEVEL = cfg.get("httpLogLevel", "ERROR").upper()
STATE_SAVE_INTERVAL = cfg.get("stateSaveIntervalMinutes", 30)
TELEGRAM_URL = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage" if TELEGRAM_ENABLED else None

# === Data ===
arpTable = {}    # ip -> {macs:[...], vendors:[...], hostname, firstSeen, lastSeen}
lastAlertTime = {}   # ip -> datetime
stateLock = threading.Lock()
stateSavePending = threading.Event()
paused = False

# === Local time helper ===
def local_now():
  return datetime.now().astimezone()

# === OUI Update ===
OUI_URL = "https://standards-oui.ieee.org/oui.txt"
oui_dict = {}
oui_cache = {}

def updateOUIFile():
  if os.path.exists(OUI_FILE):
    mtime = os.path.getmtime(OUI_FILE)
    if (time.time() - mtime)/3600 < 24:
      return
  print("[INFO] Downloading latest OUI database...", flush=True)
  try:
    headers = {
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
              "AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/115.0.0.0 Safari/537.36"
    }
    r = requests.get(OUI_URL, headers=headers, timeout=10)
    r.raise_for_status()
    os.makedirs(os.path.dirname(OUI_FILE), exist_ok=True)
    with open(OUI_FILE, "wb") as f:
      f.write(r.content)
    print("[INFO] OUI database updated successfully.", flush=True)
  except Exception as e:
    print(f"[ERROR] Failed to update OUI database: {e}", flush=True)

def loadOUI():
  global oui_dict
  if os.path.exists(OUI_FILE):
    with open(OUI_FILE) as f:
      for line in f:
        if "(hex)" in line:
          parts = line.split()
          prefix = parts[0].replace("-", "")
          vendor = " ".join(parts[2:])
          oui_dict[prefix] = vendor

def getOUI(mac):
  prefix = mac.upper().replace(":", "")[:6]
  if prefix in oui_cache:
    return oui_cache[prefix]
  vendor = oui_dict.get(prefix, "Unknown Vendor")
  oui_cache[prefix] = vendor
  return vendor

updateOUIFile()
loadOUI()

# === Utilities ===
def sendTelegramAlert(message):
  if not TELEGRAM_ENABLED:
    return
  try:
    requests.post(TELEGRAM_URL, data={"chat_id": CHAT_ID, "text": message}, timeout=5)
  except Exception as e:
    print(f"[ERROR] Telegram alert failed: {e}", flush=True)

def getHostname(ip):
  try:
    return socket.gethostbyaddr(ip)[0]
  except:
    return ""

def ipToTuple(ip):
  return tuple(int(x) for x in ip.split("."))

def cleanupOldEntries():
  now = local_now()
  removed = []
  for ip, data in list(arpTable.items()):
    if now - data["lastSeen"] > ENTRY_TIMEOUT:
      removed.append(ip)
      del arpTable[ip]
  if removed:
    print(f"[INFO] Removed expired IP entries: {removed}", flush=True)

# === Persistence ===
def saveState():
  with stateLock:
    cleanupOldEntries()
    tmpfile = STATE_FILE + ".tmp"
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    serializable = {}
    for ip, data in arpTable.items():
      serializable[ip] = {
        "macs": data["macs"],
        "vendors": data["vendors"],
        "hostname": data["hostname"],
        "firstSeen": data["firstSeen"].isoformat(),
        "lastSeen": data["lastSeen"].isoformat()
      }
    try:
      with open(tmpfile, "w") as f:
        json.dump(serializable, f, indent=2)
      os.replace(tmpfile, STATE_FILE)
      print(f"[INFO] State saved to {STATE_FILE}", flush=True)
    except Exception as e:
      print(f"[ERROR] Failed to save state: {e}", flush=True)

def loadState():
  if os.path.exists(STATE_FILE):
    try:
      with open(STATE_FILE) as f:
        data = json.load(f)
      for ip, v in data.items():
        arpTable[ip] = {
          "macs": v["macs"],
          "vendors": v["vendors"],
          "hostname": v["hostname"],
          "firstSeen": datetime.fromisoformat(v["firstSeen"]),
          "lastSeen": datetime.fromisoformat(v["lastSeen"])
        }
      print(f"[INFO] Loaded state from {STATE_FILE}", flush=True)
    except Exception as e:
      print(f"[ERROR] Failed to load state: {e}", flush=True)

def requestSave():
  stateSavePending.set()

def backgroundStateSaver():
  while True:
    stateSavePending.wait(timeout=5)
    if stateSavePending.is_set():
      saveState()
      stateSavePending.clear()

threading.Thread(target=backgroundStateSaver, daemon=True).start()

def periodicSaveThread():
  interval_sec = STATE_SAVE_INTERVAL * 60
  while True:
    time.sleep(interval_sec)
    requestSave()

# === Shutdown Handler ===
def handleExit(signum, frame):
  print("[INFO] Received termination signal, saving state...", flush=True)
  saveState()
  os._exit(0)

signal.signal(signal.SIGTERM, handleExit)
signal.signal(signal.SIGINT, handleExit)

loadState()
threading.Thread(target=periodicSaveThread, daemon=True).start()

# === HTML Generation ===
def generateHtmlPage():
  global lastHtml
  rows = []
  with stateLock:
    sorted_ips = sorted(arpTable.keys(), key=ipToTuple)
    for ip in sorted_ips:
      data = arpTable[ip]
      macs = "<br>".join(data["macs"])
      vendors = "<br>".join(data["vendors"])
      hostname = data["hostname"]
      conflict = len(data["macs"]) > 1
      row_class = "conflict" if conflict else ""
      rows.append(f"<tr class='{row_class}'><td>{ip}</td><td>{hostname}</td><td>{macs}</td><td>{vendors}</td></tr>")

  html = f"""<!DOCTYPE html>
<html translate="no">
<head>
<title>ARP Monitor</title>
<link rel="icon" type="image/png" href="arpmon.png">
<link rel="stylesheet" href="style.css">
<script>
let paused = false;
function togglePause() {{
  paused = !paused;
  document.getElementById('pauseBtn').innerText = paused ? "Resume" : "Pause";
}}
function refreshPage() {{
  if(!paused) window.location.reload();
}}
setInterval(refreshPage, 5000);
</script>
</head>
<body>
<h2>ARP Monitor</h2>
<button id="pauseBtn" onclick="togglePause()">Pause</button>
<table>
<tr><th>IP</th><th>Hostname</th><th>MAC(s)</th><th>Vendor(s)</th></tr>
{''.join(rows)}
</table>
</body>
</html>"""
  return html

# === HTTP Server ===
class httpHandler(BaseHTTPRequestHandler):
  def log_message(self, format, *args):
    if HTTP_LOG_LEVEL == "DEBUG":
      super().log_message(format, *args)

  def do_GET(self):
    if self.path == "/":
      content = generateHtmlPage()
      self.send_response(200)
      self.send_header("Content-type", "text/html")
      self.end_headers()
      self.wfile.write(content.encode())
    elif self.path.endswith(".css"):
      self.send_response(200)
      self.send_header("Content-type", "text/css")
      self.end_headers()
      with open(CSS_FILE) as f:
        self.wfile.write(f.read().encode())
    elif self.path.endswith(".png"):
      self.send_response(200)
      self.send_header("Content-type", "image/png")
      self.end_headers()
      with open(FAVICON_FILE, "rb") as f:
        self.wfile.write(f.read())
    else:
      self.send_response(404)
      self.end_headers()

def runHttpServer():
  server = HTTPServer(("0.0.0.0", HTTP_PORT), httpHandler)
  print(f"[INFO] HTTP server running on port {HTTP_PORT}", flush=True)
  server.serve_forever()

# === ARP Sniffing ===
def handleArpReply(pkt):
  if ARP in pkt and pkt[ARP].op == 2:
    src_ip = pkt[ARP].psrc
    src_mac = pkt[ARP].hwsrc
    now = local_now()

    # Always log ARP reply
    print(f"[ARP] {now.strftime('%Y-%m-%d %H:%M:%S %Z')} - {src_ip} is at {src_mac}", flush=True)

    with stateLock:
      if src_ip not in arpTable:
        hostname = getHostname(src_ip)
        vendor = getOUI(src_mac)
        arpTable[src_ip] = {
          "macs": [src_mac],
          "vendors": [vendor],
          "hostname": hostname,
          "firstSeen": now,
          "lastSeen": now
        }
        requestSave()
      else:
        data = arpTable[src_ip]
        if src_mac not in data["macs"]:
          vendor = getOUI(src_mac)
          data["macs"].append(src_mac)
          data["vendors"].append(vendor)
          data["lastSeen"] = now
          requestSave()
          # Conflict alert
          last_alert = lastAlertTime.get(src_ip, datetime.min)
          if (now - last_alert).total_seconds() > ALERT_COOLDOWN:
            alert = (
              f"⚠️ IP Conflict Detected\n"
              f"Time: {now.strftime('%Y-%m-%d %H:%M:%S %Z')}\n"
              f"IP: {src_ip}\n"
              f"New MAC: {src_mac}\n"
              f"Old MACs: {', '.join(data['macs'][:-1])}"
            )
            print(alert, flush=True)
            sendTelegramAlert(alert)
            lastAlertTime[src_ip] = now
        else:
          data["lastSeen"] = now

if __name__ == "__main__":
  threading.Thread(target=runHttpServer, daemon=True).start()
  print("Monitoring ARP replies for potential IP conflicts...", flush=True)
  sniff(filter="arp", prn=handleArpReply, store=0)
