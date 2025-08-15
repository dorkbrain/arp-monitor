# arp-monitor
Python script to monitor and log ARP brodcasts and track IP conflicts

### Step 1: Install dependencies
```
sudo apt update
sudo apt install python3-scapy python3-requests
```

### Step 2: Create the `arpmon` service account
```
sudo useradd -r -s /usr/sbin/nologin arpmon
```

### Step 3: Create required directories and copy files with permissions
```
# Config directory
sudo mkdir -p /etc/arp-monitor
sudo cp /opt/arp-monitor-src/config/config.json /etc/arp-monitor/
sudo chown -R arpmon:arpmon /etc/arp-monitor
sudo chmod 644 /etc/arp-monitor/config.json

# Script and web assets
sudo mkdir -p /opt/arp-monitor
sudo cp -r /opt/arp-monitor-src/src/* /opt/arp-monitor/
sudo cp -r /opt/arp-monitor-src/web/* /opt/arp-monitor/
sudo chown -R arpmon:arpmon /opt/arp-monitor
sudo chmod 755 /opt/arp-monitor/arp-monitor.py
sudo chmod 644 /opt/arp-monitor/*.css /opt/arp-monitor/*.png

# State and OUI files
sudo mkdir -p /var/lib/arp-monitor
sudo chown -R arpmon:arpmon /var/lib/arp-monitor
sudo chmod 755 /var/lib/arp-monitor
```

### Step 4: Configure systemd service
```
sudo cp /opt/arp-monitor-src/systemd/arp-monitor.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now arp-monitor.service
sudo systemctl status arp-monitor.service
```

### Step 5: Access the web interface
Open a browser on your network: `http://<server-ip>:8080`
