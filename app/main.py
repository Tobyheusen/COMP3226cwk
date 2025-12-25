# FastAPI application entry point that initialises 
# the app and registers API routes.


from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from app.routes.auth import router as auth_router, store
from app.core.config import settings
import qrcode
import io
import base64

app = FastAPI(title="QR Login Prototype")
app.include_router(auth_router)

@app.get("/health")
def health():
    return {"ok": True}

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    # Create a new session
    session = store.create()
    
    # Generate scan URL
    base = str(request.base_url).rstrip("/")
    scan_url = f"{base}/auth/scan?s_id={session.session_id}&nonce={session.approval_nonce}"
    
    # Generate QR code
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(scan_url)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)
    qr_image_base64 = base64.b64encode(buffer.getvalue()).decode()
    
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
                <img src="data:image/png;base64,{qr_image_base64}" alt="QR Code" />
            </div>
            <div id="status" class="pending">Waiting for scan...</div>
        </div>
        <script>
            const sessionId = '{session.session_id}';
            const pollInterval = {settings.POLL_MIN_INTERVAL_MS};
            let pollTimer = null;
            
            function updateStatus(status, message) {{
                const statusEl = document.getElementById('status');
                statusEl.className = status;
                statusEl.textContent = message;
            }}
            
            async function pollStatus() {{
                try {{
                    const response = await fetch(`/auth/poll?session_id=${{sessionId}}`);
                    const data = await response.json();
                    
                    if (data.status === 'approved') {{
                        updateStatus('approved', '✓ Approved! Exchanging for token...');
                        clearInterval(pollTimer);
                        
                        // Exchange for token
                        const exchangeResponse = await fetch('/auth/exchange', {{
                            method: 'POST',
                            headers: {{ 'Content-Type': 'application/json' }},
                            body: JSON.stringify({{ s_id: sessionId }})
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
            
            // Start polling
            pollTimer = setInterval(pollStatus, pollInterval);
            pollStatus(); // Initial poll
        </script>
    </body>
    </html>
    """
    
    return HTMLResponse(content=html_content)
