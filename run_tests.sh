#!/bin/bash
set -e

echo "Installing dependencies..."
pip install -r requirements.txt

echo "Starting server..."
uvicorn app.main:app --host 127.0.0.1 --port 8000 > server.log 2>&1 &
SERVER_PID=$!
echo "Server started with PID $SERVER_PID"

# Wait for server to be ready
echo "Waiting for server to launch..."
sleep 5

echo "Running tests..."
python3 tests/test_flow.py
python3 tests/test_replay.py

echo "Tests completed successfully."
kill $SERVER_PID
rm server.log
