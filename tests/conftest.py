import pytest
import observability

@pytest.fixture(autouse=True)
def _reset_price_cache():
    observability._price_cache["price"] = None
    observability._price_cache["ts"] = 0.0
    observability._price_cache["retry_after"] = 0.0
    yield
    observability._price_cache["price"] = None
    observability._price_cache["ts"] = 0.0
    observability._price_cache["retry_after"] = 0.0
