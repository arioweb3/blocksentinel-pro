# Demo deployment guide

A public URL cannot be provisioned by source generation alone; it requires an account and deployment target that you control. This repository is container-ready for evaluation.

## Local preview

```bash
pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

## Container

```bash
docker build -t blocksentinel-pro .
docker run --rm -p 8000:8000 blocksentinel-pro
```

## Before making it public

1. Put the app behind HTTPS and a reverse proxy.
2. Add authentication, rate limiting, and usage quotas.
3. Add an isolated analysis worker for Slither and solc calls.
4. Disable outbound network access from workers unless strictly required.
5. Publish a privacy and retention policy.
6. Add monitoring, logs without source contents, and abuse reporting.
7. Make the demo clearly state that source is not persisted only if that remains true in your deployment.

Never advertise the site as a live blockchain connection unless a real RPC integration is implemented. The animated hero is explicitly a visual simulation.
