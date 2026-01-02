# FastAPI application entry point that initialises 
# the app and registers API routes.


from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from app.routes.auth import router as auth_router
from app.core.config import settings

app = FastAPI(title="QR Login Prototype")
app.include_router(auth_router)

@app.get("/health")
def health():
    return {"ok": True}

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    # HTML page with JS that initiates the session
    # RQ1: Browser generates a key, sends to server, and binds session.
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>QR Login</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                display: flex;
                flex-direction: column;
                align-items: center;
                justify-content: center;
                min-height: 100vh;
                margin: 0;
                background: #f5f5f5;
            }}
            .container {{
                background: white;
                padding: 2rem;
                border-radius: 10px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                text-align: center;
            }}
            h1 {{
                color: #333;
                margin-bottom: 1rem;
            }}
            #qr-code {{
                margin: 1rem 0;
                min-height: 150px;
                display: flex;
                align-items: center;
                justify-content: center;
            }}
            #status {{
                margin-top: 1rem;
                padding: 0.5rem;
                border-radius: 5px;
                font-weight: bold;
            }}
            .pending {{
                color: #666;
                background: #f0f0f0;
            }}
            .approved {{
                color: #28a745;
                background: #d4edda;
            }}
            .error {{
                color: #dc3545;
                background: #f8d7da;
            }}
            .expired {{
                color: #856404;
                background: #fff3cd;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>QR Code Login</h1>
            <p>Scan this QR code with your phone to log in</p>
            <div id="qr-code">
                Loading...
            </div>
            <div id="status" class="pending">Initializing...</div>
        </div>
        <script>
            let sessionId = null;
            let browserKey = null;
            const pollInterval = {settings.POLL_MIN_INTERVAL_MS};
            let pollTimer = null;
            
            function generateBrowserKey() {{
                // RQ1: Generate a random browser key (proof of possession)
                return Array.from(crypto.getRandomValues(new Uint8Array(32)))
                    .map(b => b.toString(16).padStart(2, '0')).join('');
            }}

            function updateStatus(status, message) {{
                const statusEl = document.getElementById('status');
                statusEl.className = status;
                statusEl.textContent = message;
            }}
            
            async function initSession() {{
                try {{
                    browserKey = localStorage.getItem('qr_browser_key');
                    if (!browserKey) {{
                        browserKey = generateBrowserKey();
                        localStorage.setItem('qr_browser_key', browserKey);
                    }}

                    const response = await fetch('/auth/session', {{
                        method: 'POST',
                        headers: {{ 'Content-Type': 'application/json' }},
                        body: JSON.stringify({{ browser_key: browserKey }})
                    }});

                    if (!response.ok) {{
                        throw new Error('Failed to create session');
                    }}

                    const data = await response.json();
                    sessionId = data.s_id;

                    const qrImg = document.createElement('img');
                    qrImg.src = "data:image/png;base64," + data.qr_image;
                    qrImg.alt = "QR Code";

                    const qrContainer = document.getElementById('qr-code');
                    qrContainer.innerHTML = '';
                    qrContainer.appendChild(qrImg);

                    updateStatus('pending', 'Waiting for scan...');

                    // Start polling
                    pollTimer = setInterval(pollStatus, pollInterval);
                    pollStatus();

                }} catch (error) {{
                    console.error('Init error:', error);
                    updateStatus('error', '✗ Error initializing session');
                }}
            }}

            async function pollStatus() {{
                if (!sessionId) return;

                try {{
                    const response = await fetch(`/auth/poll?session_id=${{sessionId}}`);
                    const data = await response.json();
                    
                    if (data.status === 'approved') {{
                        updateStatus('approved', '✓ Approved! Exchanging for token...');
                        clearInterval(pollTimer);
                        
                        // RQ1: Exchange for token providing browserKey
                        const exchangeResponse = await fetch('/auth/exchange', {{
                            method: 'POST',
                            headers: {{ 'Content-Type': 'application/json' }},
                            body: JSON.stringify({{ s_id: sessionId, browser_key: browserKey }})
                        }});
                        
                        if (exchangeResponse.ok) {{
                            const tokenData = await exchangeResponse.json();
                            updateStatus('approved', '✓ Login successful! Token: ' + tokenData.access_tkn.substring(0, 20) + '...');
                        }} else {{
                            updateStatus('error', '✗ Failed to exchange token');
                        }}
                    }} else if (data.status === 'expired') {{
                        updateStatus('expired', '✗ Session expired. Please refresh the page.');
                        clearInterval(pollTimer);
                    }} else if (data.status === 'consumed') {{
                        updateStatus('error', '✗ Session already used');
                        clearInterval(pollTimer);
                    }} else if (data.status === 'not_found') {{
                        updateStatus('error', '✗ Session not found');
                        clearInterval(pollTimer);
                    }}
                }} catch (error) {{
                    console.error('Poll error:', error);
                    updateStatus('error', '✗ Error checking status');
                }}
            }}
            
            // Start
            initSession();
        </script>
    </body>
    </html>
    """
    
    return HTMLResponse(content=html_content)
