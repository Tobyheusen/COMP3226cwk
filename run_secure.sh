#!/bin/bash
# Runs Uvicorn with mTLS enabled (REQUIRED client auth)
# This forces ALL connections to provide a valid client certificate.
# To use the app, you MUST import certs/client.p12 into your Browser/Mobile.

uvicorn app.main:app \
    --reload \
    --ssl-keyfile certs/server.key \
    --ssl-certfile certs/server.crt \
    --ssl-ca-certs certs/ca.crt \
    --ssl-cert-reqs 2
