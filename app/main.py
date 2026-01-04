# FastAPI application entry point that initialises 
# the app and registers API routes.


from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from app.routes.auth import router as auth_router, store
from app.core.config import settings

import secrets

app = FastAPI(title="QR Login Prototype")
app.include_router(auth_router)

@app.get("/health")
def health():
    """
    health Simple health check endpoint
    """
    return {"ok": True}

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    """
    login_page Serves the login page with QR code and polling logic
    """
    # HTML page with QR code and polling
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
                <span class="loading">Generating secure session...</span>
            </div>
            <div id="status" class="pending">Waiting for scan...</div>
        </div>
        <script>
            // Get or Create Browser Key 
            let browserKey = localStorage.getItem('qr_browser_key');
            if (!browserKey) {{
                console.log("Generating new browser key");
                browserKey = Math.random().toString(36).substring(2) + Date.now().toString(36);
                localStorage.setItem('qr_browser_key', browserKey);
            }}

            const pollInterval = {settings.POLL_MIN_INTERVAL_MS};
            let pollTimer = null;
            let sessionId = null;

            function updateStatus(cls, message) {{
                const statusEl = document.getElementById('status');
                statusEl.className = cls;
                statusEl.textContent = message;
            }}

            async function initSession() {{
                try {{
                    // Request new session, passing the browserKey
                    const res = await fetch('/auth/session', {{
                        method: 'POST',
                        headers: {{ 'Content-Type': 'application/json' }},
                        body: JSON.stringify({{ BROWSER_KEY: browserKey }})
                    }});
                    
                    if (!res.ok) throw new Error('Failed to create session');
                    
                    const data = await res.json();
                    sessionId = data.s_id;

                    // Render QR Code
                    const img = document.createElement('img');
                    img.src = "data:image/png;base64," + data.qr_base64;
                    const qrContainer = document.getElementById('qr-code');
                    qrContainer.innerHTML = '';
                    qrContainer.appendChild(img);
                    
                    updateStatus('pending', 'Waiting for scan...');
                    
                    // 4. Start Polling
                    pollTimer = setInterval(pollStatus, pollInterval);

                }} catch (e) {{
                    console.error(e);
                    updateStatus('error', 'Error initializing session');
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
                        
                        // Exchange for token (Secure Mode requires browserKey)
                        const exchangeResponse = await fetch('/auth/exchange', {{
                            method: 'POST',
                            headers: {{ 'Content-Type': 'application/json' }},
                            body: JSON.stringify({{ 
                                s_id: sessionId,
                                BROWSER_KEY: browserKey 
                            }})
                        }});
                        
                        if (exchangeResponse.ok) {{
                            const tokenData = await exchangeResponse.json();
                            updateStatus('approved', '✓ Login successful!');
                            console.log("Token:", tokenData.access_tkn);
                            // Redirect or store token here
                        }} else {{
                            updateStatus('error', '✗ Failed to exchange token');
                        }}
                    }} else if (data.status === 'expired') {{
                        updateStatus('expired', '✗ Session expired. Refresh page.');
                        clearInterval(pollTimer);
                    }}
                }} catch (error) {{
                    console.error('Poll error:', error);
                }}
            }}
            
            // Start
            initSession();
        </script>
    </body>
    </html>
    """
    
    return HTMLResponse(content=html_content)
