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

# Usage: after running **uvicorn app.main:app --reload** 
# Open using this link: http://192.168.1.40:8000/login

python -m venv venv
./venv/Scripts/Activate.ps1
pip install -r requirements.txt
$env:BASE_URL = "http://192.168.1.40:8000"
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
