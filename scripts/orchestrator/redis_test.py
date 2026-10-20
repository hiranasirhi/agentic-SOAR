import redis

r = redis.Redis(
    host="100.71.186.0",   # Replace with your friend's Tailscale IP
    port=6379,
    decode_responses=True
)

r.set("test", "hello")
print(r.get("test"))