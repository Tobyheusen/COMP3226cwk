# COMP3226 - QR Login Prototype

This project is a **locally hosted QR-code login prototype** built with **Python** and **FastAPI**.
It demonstrates **Device Bound Session Credentials (DBSC)** using hardware-protected key pairs (simulated via Web Crypto API) and **Proof of Possession**.

## Prerequisites

- **Python:** 3.10 or higher
- **Git:** For version control

## Installation

1.  Create and activate virtual environment:
    ```bash
    # macOS / Linux
    python3 -m venv venv
    source venv/bin/activate

    # Windows (PowerShell)
    python -m venv venv
    ./venv/Scripts/Activate.ps1
    ```

2.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

## Running the Application

To ensure the features work correctly on physical devices (mobile phones), the application must run over **HTTPS**. We have provided a helper script to automate this.

1.  Run the helper script:
    ```bash
    python run.py
    ```

    This script will:
    - Generate self-signed SSL certificates (`cert.pem`, `key.pem`) if needed.
    - Detect your LAN IP address.
    - Start the server on `0.0.0.0:8000`.

2.  **Access from Desktop:**
    - Look for the **LAN URL** printed in the console (e.g., `https://192.168.1.X:8000`).
    - Open that URL in your browser.
    - **Accept the security warning** (since the cert is self-signed).

3.  **Scan with Mobile:**
    - Click "Start Login" on the desktop.
    - Scan the QR code with your mobile device.
    - **Note:** Your mobile device must be on the **same Wi-Fi network**.
    - If your mobile browser blocks the self-signed certificate, you may need to visit `https://<LAN_IP>:8000` on your mobile browser first to accept the warning.

## Troubleshooting

- **"Web Crypto API not available"**: Ensure you are using `https://` or `http://localhost`. HTTP on a LAN IP is NOT a Secure Context.
- **"Could not connect to server"**: Ensure both devices are on the same network. Check your firewall settings.
