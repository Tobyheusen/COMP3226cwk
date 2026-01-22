# Helper function to run a single test scenario
function Invoke-TestScenario {
    param (
        [string]$ScenarioName,
        [string]$ServerScript,
        [string]$TestCommand,
        [hashtable]$EnvVars,
        [int]$WaitTime = 3 # Seconds to wait for server to start
    )

    Write-Host "----------------------------------------------------" -ForegroundColor Cyan
    Write-Host "STARTING SCENARIO: $ScenarioName" -ForegroundColor Cyan
    Write-Host "----------------------------------------------------"

    # 1. Set Environment Variables
    foreach ($key in $EnvVars.Keys) {
        Set-Item -Path "env:$key" -Value $EnvVars[$key]
        Write-Host "Set env:$key = $($EnvVars[$key])" -ForegroundColor DarkGray
    }

    # 2. Start the Server in the background
    Write-Host "Starting server ($ServerScript)..." -ForegroundColor Yellow
    $serverProcess = Start-Process python -ArgumentList $ServerScript -PassThru -NoNewWindow
    
    # 3. Wait for server to initialize
    Start-Sleep -Seconds $WaitTime

    # 4. Run the Pytest command
    Write-Host "Running tests..." -ForegroundColor Green
    try {
        Invoke-Expression $TestCommand
    }
    catch {
        Write-Error "Test execution failed."
    }

    # 5. Stop the Server
    Write-Host "Stopping server (PID: $($serverProcess.Id))..." -ForegroundColor Yellow
    Stop-Process -Id $serverProcess.Id -Force -ErrorAction SilentlyContinue
    
    # 6. Clean up Environment Variables (Optional but good practice)
    foreach ($key in $EnvVars.Keys) {
        Remove-Item -Path "env:$key" -ErrorAction SilentlyContinue
    }
    
    Write-Host "Scenario Finished.`n"
}

# --- RQ1 SCENARIOS ---

Invoke-TestScenario -ScenarioName "RQ1 - Secure Binding" `
    -ServerScript "run.py" `
    -TestCommand "pytest tests/test_binding_comparison.py::TestWithBinding_SecureMode -v -s" `
    -EnvVars @{ SECURITY_MODE="secure" }

Invoke-TestScenario -ScenarioName "RQ1 - Insecure No Binding" `
    -ServerScript "run.py" `
    -TestCommand "pytest tests/test_binding_comparison.py::TestWithoutBinding_InsecureMode -v -s" `
    -EnvVars @{ SECURITY_MODE="insecure" }

# --- RQ2 SCENARIOS ---

Invoke-TestScenario -ScenarioName "RQ2 - Secure mTLS Short Lifespan" `
    -ServerScript "run_mtls.py" `
    -TestCommand "pytest tests/test_token_lifespan_bruteforce.py::TestShortLifespanTokens -v -s" `
    -EnvVars @{ SECURITY_MODE="secure" }

Invoke-TestScenario -ScenarioName "RQ2 - Insecure Long Lifespan" `
    -ServerScript "run.py" `
    -TestCommand "pytest tests/test_token_lifespan_bruteforce.py::TestLongLifespanTokens -v -s" `
    -EnvVars @{ SECURITY_MODE="insecure" }

# --- SPECIAL CASES ---

Invoke-TestScenario -ScenarioName "Low-Entropy Test" `
    -ServerScript "run.py" `
    -TestCommand "pytest tests/test_token_lifespan_bruteforce.py::TestLongLifespanTokens::test_low_entropy_bruteforce_demo -v -s" `
    -EnvVars @{ 
        SECURITY_MODE="insecure"; 
        LOW_ENTROPY_LOGIN_IDS="1"; 
        INSECURE_LOGIN_ID_DIGITS="4"; 
        ENABLE_LOW_ENTROPY_DEMO="1" 
    }

Invoke-TestScenario -ScenarioName "Rate-Limit Test" `
    -ServerScript "run.py" `
    -TestCommand "pytest tests/test_token_lifespan_bruteforce.py::TestShortLifespanTokens::test_rate_limit_polling_in_secure_mode -v -s" `
    -EnvVars @{ 
        SECURITY_MODE="secure"; 
        RATE_LIMIT_ENABLED="1"; 
        RATE_LIMIT_MAX_REQUESTS="5"; 
        RATE_LIMIT_WINDOW_SECONDS="1" 
    }

Write-Host "ALL TESTS COMPLETED." -ForegroundColor Cyan