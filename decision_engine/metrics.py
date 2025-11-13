from prometheus_client import Counter, Histogram

# Total request counter dengan label 'decision' (allow/block)
REQUESTS_TOTAL = Counter(
    'requests_total',
    'Total number of requests handled',
    ['decision']
)

REQUEST_SUCCESS_TOTAL = Counter(
    'request_success_total',
    'Total number of successful requests',
    ['status']
)

REQUEST_FAIL_TOTAL = Counter(
    'request_fail_total',
    'Total number of failed requests',
    ['status']
)


# Risk score bucket histogram
RISK_SCORE_BUCKET = Histogram(
    'risk_score_bucket',
    'Distribution of risk scores',
    buckets=[-10, -5, 0, 1, 2, 5, 10]
)

# Rate limit hits (jika kamu punya rate limiter)
RATE_LIMIT_HITS = Counter(
    'rate_limit_hits',
    'Number of requests rejected due to rate limiting',
    ['ip', 'tenant']
)

HMAC_USED_TOTAL = Counter(
    'hmac_used_total',
    'Number of requests that include HMAC signature',
    ['result']  # bisa diganti dengan label lain kalau perlu
)

# Cache status counter
CACHE_HIT = Counter(
    'cache_hit',
    'Number of backend cache hits'
)

CACHE_MISS = Counter(
    'cache_miss',
    'Number of backend cache misses'
)

GEO_BLOCK_TOTAL = Counter(
    'geoblock_total',
    'GeoBlock decision result (blocked or allowed)',
    ['result']
)
