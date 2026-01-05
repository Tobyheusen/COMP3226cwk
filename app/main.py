from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from app.routes import auth

app = FastAPI(title="QR Login Prototype")

app.include_router(auth.router)

@app.get("/", response_class=HTMLResponse)
def root():
    return """
    <html>
        <head>
            <title>QR Login</title>
        </head>
        <body>
            <h1>QR Code Login Prototype</h1>
            <p><a href="/login">Go to Login Page</a></p>
        </body>
    </html>
    """

@app.get("/login", response_class=HTMLResponse)
def login_page():
    return """
    <html>
        <head>
            <title>Login</title>
            <script>
                let loginId = null;
                // Generate a random browser key for DBSC simulation
                const browserKey = "browser-key-" + Math.random().toString(36).substr(2, 9);

                async function startLogin() {
                    console.log("Using browser key:", browserKey);

                    try {
                        const response = await fetch('/auth/init', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({ browser_key: browserKey })
                        });

                        if (!response.ok) {
                            const err = await response.json();
                            document.getElementById('status').innerText = "Error: " + err.detail;
                            return;
                        }

                        const data = await response.json();
                        loginId = data.login_id;
                        document.getElementById('qr-image').src = "data:image/png;base64," + data.qr_image;
                        document.getElementById('status').innerText = "Scan the QR code with your device.";
                        document.getElementById('raw-payload').innerText = data.qr_payload;

                        pollStatus();
                    } catch (e) {
                        document.getElementById('status').innerText = "Connection Error: " + e;
                    }
                }

                async function pollStatus() {
                    if (!loginId) return;

                    const interval = setInterval(async () => {
                        const response = await fetch('/auth/poll/' + loginId);
                        const data = await response.json();

                        if (data.status === 'AUTHORIZED') {
                            document.getElementById('status').innerText = "Login Successful! Token: " + data.session_token;
                            clearInterval(interval);
                        } else if (data.status === 'SCANNED') {
                             document.getElementById('status').innerText = "QR Scanned! Waiting for approval...";
                        } else if (data.status === 'EXPIRED') {
                             document.getElementById('status').innerText = "QR Expired. Please refresh.";
                             clearInterval(interval);
                        }
                    }, 2000);
                }

                window.onload = startLogin;
            </script>
        </head>
        <body>
            <h1>Scan this QR Code</h1>
            <div id="status">Loading...</div>
            <img id="qr-image" style="border: 1px solid #ccc; padding: 10px;"/>

            <hr>
            <h3>Simulation Tools (Mobile Device)</h3>
            <p>Copy the raw payload below to simulate scanning:</p>
            <textarea id="raw-payload" rows="4" cols="50" readonly></textarea>
            <br>
            <button onclick="simulateScan()">Simulate Scan</button>
            <button onclick="simulateApprove()">Simulate Approve</button>
            <div id="sim-result"></div>

            <script>
                async function simulateScan() {
                    const payload = document.getElementById('raw-payload').value;
                    const response = await fetch('/auth/scan', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({ qr_raw_payload: payload })
                    });

                    const res = await response.json();
                    if (!response.ok) {
                         document.getElementById('sim-result').innerText = "Scan Failed: " + (res.detail || JSON.stringify(res));
                    } else {
                         document.getElementById('sim-result').innerText = "Scan Result: " + JSON.stringify(res);
                    }
                }

                async function simulateApprove() {
                    if (!loginId) return;
                    const response = await fetch('/auth/approve', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({ login_id: loginId, user_id: "alice" })
                    });
                    const res = await response.json();
                    document.getElementById('sim-result').innerText = "Approve Result: " + JSON.stringify(res);
                }
            </script>
        </body>
    </html>
    """
