import sys
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

# Ensure root dir is in sys.path
root_dir = Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from rent_service import app, ip_request_counts

client = TestClient(app)

def test_security_headers_and_rate_limit():
    # Clear rate limit memory for isolated test execution
    ip_request_counts.clear()

    # 1. Test security headers presence
    response = client.get("/claime")
    assert response.status_code == 200
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert "Content-Security-Policy" in response.headers

    # 2. Test rate limiting on /api/ routes (flood 12 requests)
    res = None
    for i in range(12):
        res = client.post("/api/rent/confirm", json={"signature": "fake", "wallet": "fake"})

    # 12th request in the window must trigger HTTP 429
    assert res is not None
    assert res.status_code == 429
    assert "Rate limit exceeded" in res.json().get("detail", "")

def test_analytics_and_stats_endpoints():
    ip_request_counts.clear()

    # 1. Track cookieless event
    resp_track = client.post("/api/analytics/track", json={"event_type": "page_view"})
    assert resp_track.status_code == 200
    assert resp_track.json() == {"status": "tracked"}

    # 2. Fetch stats
    resp_stats = client.get("/api/rent/stats")
    assert resp_stats.status_code == 200
    data = resp_stats.json()
    assert "total_claims" in data
    assert "total_sol_reclaimed" in data

def test_reverse_proxy_ip_rate_limiting_isolation():
    ip_request_counts.clear()

    # Client A behind Nginx proxy with X-Forwarded-For
    headers_a = {"X-Forwarded-For": "203.0.113.195, 127.0.0.1"}
    for _ in range(9):
        resp = client.post("/api/analytics/track", json={"event_type": "click"}, headers=headers_a)
        assert resp.status_code == 200

    # Client B behind same Nginx proxy should NOT be throttled by Client A
    headers_b = {"X-Forwarded-For": "198.51.100.42, 127.0.0.1"}
    resp_b = client.post("/api/analytics/track", json={"event_type": "click"}, headers=headers_b)
    assert resp_b.status_code == 200

    # 10th and 11th request for Client A triggers rate limit only for Client A
    client.post("/api/analytics/track", json={"event_type": "click"}, headers=headers_a)
    resp_a_blocked = client.post("/api/analytics/track", json={"event_type": "click"}, headers=headers_a)
    assert resp_a_blocked.status_code == 429

    # Client B remains unblocked
    resp_b_still_ok = client.post("/api/analytics/track", json={"event_type": "click"}, headers=headers_b)
    assert resp_b_still_ok.status_code == 200