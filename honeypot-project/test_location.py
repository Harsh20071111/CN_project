import requests

def get_location(ip):
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=2)
        if res.status_code == 200:
            data = res.json()
            return f"{data.get('city', 'Unknown')}, {data.get('country', 'Unknown')}"
    except Exception as e:
        return f"Error: {e}"
    return "Unknown"

print("Testing Google DNS (8.8.8.8):", get_location("8.8.8.8"))
print("Testing Cloudflare (1.1.1.1):", get_location("1.1.1.1"))
