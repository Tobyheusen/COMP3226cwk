from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from app.routes import auth
from app.db import db
from app.services.auth_service import AuthService
import json

app = FastAPI(title="QR Login Prototype")

app.include_router(auth.router)

@app.get("/", response_class=HTMLResponse)
def root():
    return """
    <html>
        <head><title>QR Login</title></head>
        <body style="font-family: sans-serif; padding: 20px;">
            <h1>QR Code Login Prototype</h1>
            <ul>
                <li><a href="/login">1. Start Login (Browser)</a></li>
                <li><a href="/admin">2. Server Admin Dashboard (Approve here)</a></li>
            </ul>
        </body>
    </html>
    """

@app.get("/login", response_class=HTMLResponse)
def login_page():
    return """
    <html>
        <head>
            <title>Login</title>
            <style>body { font-family: sans-serif; padding: 20px; }</style>
            <script>
                let loginId = null;
                const browserKey = "browser-key-" + Math.random().toString(36).substr(2, 9);

                async function startLogin() {
                    try {
                        const response = await fetch('/auth/init', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({ browser_key: browserKey })
                        });

                        const data = await response.json();
                        loginId = data.login_id;
                        
                        document.getElementById('qr-image').src = "data:image/png;base64," + data.qr_image;
                        document.getElementById('status').innerText = "Scan the QR code below.";
                        
                        // Link for simulation
                        const simLink = data.qr_link;
                        document.getElementById('qr-link').href = simLink;
                        document.getElementById('qr-link').innerText = "Simulate Scan (Click Me)";
                        
                        pollStatus();
                    } catch (e) {
                        document.getElementById('status').innerText = "Error: " + e;
                    }
                }

                async function pollStatus() {
                    if (!loginId) return;
                    const interval = setInterval(async () => {
                        // Add timestamp to prevent caching
                        const response = await fetch('/auth/poll/' + loginId + '?t=' + Date.now());
                        const data = await response.json();

                        if (data.status === 'AUTHORIZED') {
                            document.getElementById('status').innerText = "✅ Login Successful!";
                            document.getElementById('token').innerText = "Session Token: " + data.session_token;
                            clearInterval(interval);
                        } else if (data.status === 'SCANNED') {
                             document.getElementById('status').innerText = "📲 QR Scanned! Waiting for Server Admin approval...";
                        } else if (data.status === 'EXPIRED') {
                             document.getElementById('status').innerText = "❌ QR Expired. Please refresh.";
                             clearInterval(interval);
                        } else if (data.status === 'NOT_FOUND') {
                             document.getElementById('status').innerText = "⚠️ Session lost (Server restarted?). Refresh page.";
                             clearInterval(interval);
                        }
                    }, 2000);
                }

                window.onload = startLogin;
            </script>
        </head>
        <body>
            <h1>User Login Page</h1>
            <div id="status" style="font-weight: bold; margin-bottom: 10px;">Loading...</div>
            <div id="token" style="color: green; word-break: break-all;"></div>
            
            <img id="qr-image" style="border: 1px solid #ccc; padding: 10px; width: 200px;"/>
            
            <p>
                <a id="qr-link" target="_blank" href="#" style="background: #007bff; color: white; padding: 10px; text-decoration: none; border-radius: 5px;">Loading Link...</a>
            </p>
        </body>
    </html>
    """

@app.get("/admin", response_class=HTMLResponse)
def admin_dashboard():
    """
    Shows a list of all login requests and allows the server admin to approve them.
    """
    rows = ""
    for req in db.login_requests.values():
        l_id = req["login_id"]
        status = req["status"]
        
        # Only show Approve button if status is SCANNED
        action_html = ""
        if status == "SCANNED":
            action_html = f"""
                <form action="/admin/approve" method="post">
                    <input type="hidden" name="login_id" value="{l_id}">
                    <button type="submit" style="background: green; color: white; cursor: pointer; padding: 5px 10px;">Approve</button>
                </form>
            """
        elif status == "AUTHORIZED":
            action_html = "<span style='color:green'>✅ Approved</span>"
        elif status == "PENDING":
             action_html = "<span style='color:gray'>Waiting for Scan...</span>"
        else:
            action_html = status

        rows += f"""
        <tr>
            <td>{l_id[:8]}...</td>
            <td>{status}</td>
            <td>{req.get("browser_sid", "")[:8]}...</td>
            <td>{action_html}</td>
        </tr>
        """

    return f"""
    <html>
        <head>
            <title>Server Admin</title>
            <meta http-equiv="refresh" content="2"> <style>
                body {{ font-family: sans-serif; padding: 20px; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <h1>Server-Side Admin Dashboard</h1>
            <p>This panel simulates the backend server forcing an approval.</p>
            <table>
                <tr>
                    <th>Login ID</th>
                    <th>Status</th>
                    <th>Browser SID</th>
                    <th>Action</th>
                </tr>
                {rows}
            </table>
            <p><small>Auto-refreshes every 2 seconds.</small></p>
        </body>
    </html>
    """

@app.post("/admin/approve")
def admin_approve(login_id: str = Form(...)):
    AuthService.approve_login(login_id, user_id="server_admin")
    return RedirectResponse(url="/admin", status_code=303)

@app.get("/mobile-sim", response_class=HTMLResponse)
def mobile_sim_page(p: str):
    """
    Simulates the Mobile App.
    1. Scans the QR automatically on load.
    2. Polls the server until the Admin approves.
    """
    payload_js = json.dumps(p)

    return f"""
    <html>
        <head>
            <title>Mobile Scanner</title>
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
                body {{ font-family: sans-serif; padding: 20px; text-align: center; }}
                .success {{ color: green; font-weight: bold; }}
                .error {{ color: red; }}
                .waiting {{ color: orange; font-weight: bold; }}
            </style>
            <script>
                const payload = {payload_js};
                let loginId = null;

                async function autoScan() {{
                    document.getElementById('status').innerText = "Scanning QR Code...";
                    
                    try {{
                        // 1. Perform Scan
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
                        document.getElementById('status').innerText = "✅ Scanned! Waiting for Admin Approval...";
                        document.getElementById('status').className = "waiting";

                        // 2. Start Polling for Approval
                        pollForApproval();
                        
                    }} catch (e) {{
                         document.getElementById('status').innerText = "Network Error: " + e;
                         document.getElementById('status').className = "error";
                    }}
                }}

                async function pollForApproval() {{
                    if (!loginId) return;
                    
                    const interval = setInterval(async () => {{
                        try {{
                            const response = await fetch('/auth/poll/' + loginId + '?t=' + Date.now());
                            const data = await response.json();

                            if (data.status === 'AUTHORIZED') {{
                                document.getElementById('status').innerHTML = "✅ APPROVED!<br>You can close this window.";
                                document.getElementById('status').className = "success";
                                clearInterval(interval);
                            }}
                        }} catch (e) {{
                            console.log("Polling error", e);
                        }}
                    }}, 2000);
                }}

                window.onload = autoScan;
            </script>
        </head>
        <body>
            <h2>Mobile Scanner</h2>
            <div id="status">Initializing...</div>
        </body>
    </html>
    """