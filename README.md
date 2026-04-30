# HTTP Port Forwarder via Google Apps Script

[![GitHub](https://img.shields.io/badge/GitHub-nya1-blue?logo=github)](https://github.com/xshayank/nya1)


| [English](README.md) | [Persian](README_FA.md) |
| :---: | :---: |

## Disclaimer

This project is provided for educational, testing, and research purposes only.

- **Provided without warranty:** This software is provided "AS IS", without express or implied warranty, including merchantability, fitness for a particular purpose, and non-infringement.
- **Limitation of liability:** The developers and contributors are not responsible for any direct, indirect, incidental, consequential, or other damages resulting from the use of this project or the inability to use it.
- **User responsibility:** Running this project outside controlled test environments may affect networks, accounts, or connected systems. You are solely responsible for installation, configuration, and use.
- **Legal compliance:** You are responsible for complying with all local, national, and international laws and regulations before using this software.
- **Google services compliance:** If you use Google Apps Script with this project, you are responsible for complying with Google's Terms of Service, acceptable use rules, quotas, and platform policies. Misuse may lead to suspension or termination of your Google account or deployments.
- **License terms:** Use, copying, distribution, and modification of this software are governed by the repository license. Any use outside those terms is prohibited.

---

## How It Works

```
Client → localhost:1080 (plain TCP) → Python forwarder → GAS (domain-fronted via www.google.com) → http://target:port
```

1. You configure a **fixed HTTP target endpoint** (e.g. `http://test.com:80`) and a **local listen port** (e.g. `1080`).
2. The Python app opens `localhost:1080` as a plain TCP/HTTP listener — **no TLS, no MITM, no certificate needed**.
3. When a client sends an HTTP request to `localhost:1080`, the app reads it and tunnels it to **Google Apps Script** (domain-fronted via `www.google.com` → `script.google.com` so the bypass works), and GAS fetches the configured target endpoint directly — **no Cloudflare Worker**.
4. The response is returned to the client.

The network only sees traffic to `www.google.com`, while your request is secretly routed to the target.

---

## How to Use

### 1 — Download the project

```bash
git clone https://github.com/xshayank/nya1.git
cd nya1
pip install -r requirements.txt
```

> **Can't reach PyPI directly?** Use this mirror instead:
> ```bash
> pip install -r requirements.txt -i https://mirror-pypi.runflare.com/simple/ --trusted-host mirror-pypi.runflare.com
> ```

### 2 — Set Up the Google Apps Script relay (Code.gs)

1. Open [Google Apps Script](https://script.google.com/) and sign in with your Google account.
2. Click **New project**.
3. **Delete** all the default code in the editor.
4. Open the [`Code.gs`](script/Code.gs) file from this project (under `script/`), **copy everything**, and paste it into the Apps Script editor.
5. **Important:** Change the following constants to match your setup:
   ```javascript
   const AUTH_KEY = "your-secret-password-here";  // must match auth_key in config.json
   const TARGET_URL = "http://test.com:80";        // the HTTP endpoint GAS will forward to
   ```
6. Click **Deploy** → **New deployment**.
7. Choose **Web app** as the type.
8. Set:
   - **Execute as:** Me
   - **Who has access:** Anyone
9. Click **Deploy**.
10. **Copy the Deployment ID** (it looks like a long random string). You'll need it in the next step.

> ⚠️ No Cloudflare Worker is needed. GAS connects to the target HTTP endpoint directly.

### 3 — Configure

Copy `config.example.json` to `config.json` and fill in your values:

```json
{
  "script_id": "YOUR_APPS_SCRIPT_DEPLOYMENT_ID",
  "auth_key": "your-secret-password-here",
  "target_url": "http://test.com:80",
  "listen_host": "127.0.0.1",
  "listen_port": 1080,
  "front_domain": "www.google.com",
  "google_ip": "216.239.38.120",
  "relay_timeout": 25,
  "log_level": "INFO"
}
```

| Field | Description |
|-------|-------------|
| `script_id` | Your Google Apps Script Deployment ID |
| `auth_key` | Shared secret — must match `AUTH_KEY` in `Code.gs` |
| `target_url` | The fixed HTTP endpoint to forward requests to |
| `listen_host` | Local bind address (default `127.0.0.1`) |
| `listen_port` | Local TCP port clients connect to (default `1080`) |
| `front_domain` | SNI domain for domain fronting (default `www.google.com`) |
| `google_ip` | Google edge IP for domain fronting (optional) |
| `relay_timeout` | Request timeout in seconds (default `25`) |

### 4 — Run

Click on the `run.bat` file (on Windows) or `run.sh` file (on Linux/macOS) to start the forwarder.

If you're running for the first time, it will prompt a setup wizard where you enter the `auth_key`, Deployment ID, and target URL.

You should see a message like:
```
Listening on 127.0.0.1:1080 → http://test.com:80 (via GAS)
```

### 5 — Connect a client

Point any HTTP client at `http://127.0.0.1:1080`. All requests will be forwarded to your configured `target_url` via the GAS relay.

> **No certificate installation needed.** This is a plain TCP port forwarder, not an MITM proxy.

---

## Using with Xray / v2ray (xhttp transport)

This forwarder is designed to work as an **xhttp transport endpoint** for Xray/v2ray.

### Xray client outbound config

Configure the Xray client to send xhttp traffic to `127.0.0.1:1080` (the forwarder's listen port).
Set `target_url` in `config.json` to your actual remote xhttp server address.

```json
{
  "outbounds": [
    {
      "tag": "proxy",
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "127.0.0.1",
            "port": 1080,
            "users": [{ "id": "YOUR-UUID", "encryption": "none" }]
          }
        ]
      },
      "streamSettings": {
        "network": "xhttp",
        "xhttpSettings": {
          "host": "127.0.0.1",
          "path": "/your-path"
        },
        "security": "none"
      }
    }
  ]
}
```

The forwarder listens on `127.0.0.1:1080`, reads the xhttp requests (including chunked/binary bodies), and tunnels them through Google Apps Script to the real remote xhttp server specified in `target_url`.

> **Note:** GAS has a 30-second execution limit per request. Set `relay_timeout` to `28` to stay safely within this limit.

