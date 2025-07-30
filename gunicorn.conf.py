bind = "0.0.0.0:5000"
workers = 4
worker_class = "sync"
worker_connections = 1000
timeout = 30
keepalive = 2
max_requests = 1000
max_requests_jitter = 100
preload_app = True

def on_starting(server):
    """Called just before the master process is initialized."""
    import os
    os.makedirs('/app/data', exist_ok=True)
    print("Data directory created")
