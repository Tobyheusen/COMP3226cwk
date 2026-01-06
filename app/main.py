from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from app.routes import auth
from app.db import db
from app.services.auth_service import AuthService
import json

"""Acts as the main FastAPI app, connects all backend routes and serves simple HTML pages for testing"""

app = FastAPI(title="QR Login Prototype")

app.include_router(auth.router)

# Page without any login, just links to start login or admin
@app.get("/", response_class=HTMLResponse)
def root(request: Request):
    base_url = str(request.base_url).rstrip("/")
    return f"""
    <html>
        <head><title>QR Login</title></head>
        <body style="font-family: sans-serif; padding: 20px;">
            <h1>QR Code Login Prototype</h1>
            <div style="background: #fff3cd; padding: 15px; border: 1px solid #ffeeba; border-radius: 5px; margin-bottom: 20px;">
                <strong>Setup Info:</strong>
                <p>Ensure you are accessing this page via <code>https://</code> (Secure Context).</p>
                <p>Current Base URL: <code>{base_url}</code></p>
                <p>If you are on a mobile device, ensure you are connected to the same network and accessing the server via its LAN IP.</p>
            </div>
            <ul>
                <li><a href="/login">1. Start Login (Browser)</a></li>
                <li><a href="/admin">2. Server Admin Dashboard (Approve here)</a></li>
            </ul>
        </body>
    </html>
    """

# Login page with Web Crypto key generation and QR code display
@app.get("/login", response_class=HTMLResponse)
def login_page():
    return """
    <html>
        <head>
            <title>Login</title>
            <style>body { font-family: sans-serif; padding: 20px; }</style>
            <script>
                let loginId = null;
                let keyPair = null;

                // Generate a Web Crypto Key Pair
                async function generateKey() {
                    // Calls generateKey() from Web Crypto API to create an RSA key pair 
                    if (!window.crypto || !window.crypto.subtle) {
                        throw new Error("Web Crypto API not available. This feature requires a Secure Context (HTTPS or localhost)");
                    }
                    return window.crypto.subtle.generateKey(
                        {
                            name: "RSASSA-PKCS1-v1_5",
                            modulusLength: 2048,
                            publicExponent: new Uint8Array([1, 0, 1]),
                            hash: "SHA-256",
                        },
                        false, 
                        ["sign", "verify"]
                    );
                }
                
                // Export the public key as JWK to server
                async function exportPublicKey(key) {
                    return await window.crypto.subtle.exportKey("jwk", key.publicKey);
                }

                // Sign data using the private key
                async function signData(dataStr) {
                    if (!window.crypto || !window.crypto.subtle) {
                         throw new Error("Web Crypto API lost/unavailable.");
                    }
                    const enc = new TextEncoder();
                    const signature = await window.crypto.subtle.sign(
                        "RSASSA-PKCS1-v1_5",
                        keyPair.privateKey,
                        enc.encode(dataStr)
                    );
                    // Convert ArrayBuffer to Base64
                    let binary = '';
                    const bytes = new Uint8Array(signature);
                    const len = bytes.byteLength;
                    for (let i = 0; i < len; i++) {
                        binary += String.fromCharCode(bytes[i]);
                    }
                    return window.btoa(binary);
                }

                async function startLogin() {
                    try {
                        document.getElementById('status').innerText = "Generating Secure Key...";
                        keyPair = await generateKey();
                        const pubKeyJWK = await exportPublicKey(keyPair);

                        // browser_key is now the stringified JWK
                        const browserKey = JSON.stringify(pubKeyJWK);

                        // send to server to initiate login
                        const response = await fetch('/auth/init', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({ browser_key: browserKey })
                        });

                        const data = await response.json();
                        // get login_id
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

                // timer runs every 2 seconds to poll status
                async function pollStatus() {
                    if (!loginId) return;
                    const interval = setInterval(async () => {
                        // Add timestamp to prevent caching
                        const response = await fetch('/auth/poll/' + loginId + '?t=' + Date.now());
                        const data = await response.json();
                        
                        // If its auth complete
                        if (data.status === 'AUTHORIZED') {
                            // If session_token is present (insecure mode), show it.
                            if (data.session_token) {
                                document.getElementById('status').innerText = "Login Successful!";
                                document.getElementById('token').innerText = "Session Token: " + data.session_token;
                                clearInterval(interval);
                                return;
                            }

                            // Secure Mode: Perform Proof of Possession
                            document.getElementById('status').innerText = "Verifying Key Possession...";

                            try {
                                const signature = await signData(loginId);
                                const tokenResp = await fetch('/auth/token', {
                                    method: 'POST',
                                    headers: {'Content-Type': 'application/json'},
                                    body: JSON.stringify({ login_id: loginId, signature: signature })
                                });

                                const tokenData = await tokenResp.json();
                                if (tokenResp.ok) {
                                    document.getElementById('status').innerText = "Login Successful (Verified)!";
                                    document.getElementById('token').innerText = "Session Token: " + tokenData.session_token;
                                } else {
                                    document.getElementById('status').innerText = "Verification Failed: " + tokenData.detail;
                                }
                            } catch (e) {
                                document.getElementById('status').innerText = "Proof of Possession Error: " + e;
                            }

                            clearInterval(interval);
                        } else if (data.status === 'SCANNED') {
                             document.getElementById('status').innerText = "QR Scanned! Waiting for Server Admin approval...";
                        } else if (data.status === 'EXPIRED') {
                             document.getElementById('status').innerText = "QR Expired. Please refresh.";
                             clearInterval(interval);
                        } else if (data.status === 'NOT_FOUND') {
                             document.getElementById('status').innerText = "Session lost (Server restarted?). Refresh page.";
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
    Shows a list of all login requests and allows the admin to approve them
    Mostly to delay the approval to simulate real-world usage
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
            action_html = "<span style='color:green'>Approved</span>"
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
    # If admin approves, approve the login as "misc" user (this does not matter much for demo)
    AuthService.approve_login(login_id, user_id="misc")
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
                        document.getElementById('status').innerText = "Scanned! Waiting for Admin Approval...";
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
                                document.getElementById('status').innerHTML = "APPROVED!<br>You can close this window.";
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