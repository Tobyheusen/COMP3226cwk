from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from app.routes import auth
import json

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
                        document.getElementById('qr-link').href = data.qr_link;
                        document.getElementById('qr-link').innerText = data.qr_link;
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
            <p>Or click this link (simulating scanning): <br> <a id="qr-link" target="_blank" href="#">Loading...</a></p>

            <hr>
            <h3>Debug Info</h3>
            <p>Raw Payload:</p>
            <textarea id="raw-payload" rows="4" cols="50" readonly></textarea>
        </body>
    </html>
    """

@app.get("/mobile-sim", response_class=HTMLResponse)
def mobile_sim_page(p: str):
    """
    Simulates the Mobile App View.
    Receives payload 'p' from the URL (QR Code).
    """
    # Safe serialization to JS string (handles quotes, backslashes, XSS)
    payload_js = json.dumps(p)

    return f"""
    <html>
        <head>
            <title>Mobile App Simulation</title>
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
                body {{ font-family: sans-serif; padding: 20px; text-align: center; }}
                button {{ padding: 15px 30px; font-size: 18px; background-color: #28a745; color: white; border: none; border-radius: 5px; cursor: pointer; }}
                button:disabled {{ background-color: #ccc; }}
                .error {{ color: red; }}
            </style>
            <script>
                const payload = {payload_js};
                let loginId = null;

                async function init() {{
                    document.getElementById('status').innerText = "Verifying QR Code...";

                    // 1. Simulate App Scanning (calls /scan)
                    try {{
                        const response = await fetch('/auth/scan', {{
                            method: 'POST',
                            headers: {{'Content-Type': 'application/json'}},
                            body: JSON.stringify({{ qr_raw_payload: payload }})
                        }});

                        const res = await response.json();
                        if (!response.ok) {{
                            document.getElementById('status').innerText = "Scan Failed: " + (res.detail || JSON.stringify(res));
                            document.getElementById('status').className = "error";
                            return;
                        }}

                        loginId = res.login_id;
                        document.getElementById('status').innerText = "Login Request Found! Do you want to approve?";
                        document.getElementById('approve-btn').disabled = false;

                    }} catch (e) {{
                         document.getElementById('status').innerText = "Network Error: " + e;
                         document.getElementById('status').className = "error";
                    }}
                }}

                async function approve() {{
                    if (!loginId) return;
                    document.getElementById('approve-btn').disabled = true;
                    document.getElementById('approve-btn').innerText = "Approving...";

                    try {{
                        const response = await fetch('/auth/approve', {{
                            method: 'POST',
                            headers: {{'Content-Type': 'application/json'}},
                            body: JSON.stringify({{ login_id: loginId, user_id: "alice" }})
                        }});

                        if (!response.ok) {{
                             document.getElementById('status').innerText = "Approval Failed.";
                             return;
                        }}

                        document.getElementById('status').innerText = "Approved! You can close this window.";
                        document.getElementById('approve-btn').style.display = 'none';

                    }} catch (e) {{
                        document.getElementById('status').innerText = "Error: " + e;
                    }}
                }}

                window.onload = init;
            </script>
        </head>
        <body>
            <h2>Mobile Authenticator</h2>
            <div id="status">Loading...</div>
            <br>
            <button id="approve-btn" onclick="approve()" disabled>Approve Login</button>
        </body>
    </html>
    """
