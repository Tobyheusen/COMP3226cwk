# COMP3226 - QR Login Prototypr (Locally ran)

This project is a **locally hosted QR-code login prototype** built with **Python** and **FastAPI**.


## Prereqs

**Python:** 3.10 or higher
**Git:** For version control


## Installation and setup

### macOS / Linux (cd Desktop/COMP3226cwk)
# Create and activate vitrual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies and run
pip install -r requirements.txt
uvicorn app.main:app --reload


### Windows (PowerShell)
# Create and activate virtual environment
python -m venv venv
./venv/Scripts/Activate.ps1

# Install dependencies and run
pip install -r requirements.txt
uvicorn app.main:app --reload

## mTLS (Mobile Channel Security)
To enable Mobile Channel Security (mTLS), you need to run the server with SSL certificates and require client authentication.

1. Generate certificates:
   `cd certs && bash gen_certs.sh`
   This creates a CA, Server Cert, and Client Cert (`client.p12`).

2. Run the secure server:
   `bash run_secure.sh`
   The server will listen on HTTPS port 8000.

3. Client Setup:
   - Import `certs/client.p12` (empty password) into your Browser and Mobile device.
   - Access: `https://localhost:8000/login`
   - If using the python test script: `python tests/test_mtls_flow.py`

# Usage: after running **uvicorn app.main:app --reload** 
# Open using this link: http://192.168.1.40:8000/login

python -m venv venv
./venv/Scripts/Activate.ps1
pip install -r requirements.txt
$env:BASE_URL = "http://192.168.1.40:8000"
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
