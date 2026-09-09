import requests
from typing import Optional


IP_API_URL = "http://ip-api.com/json"


def get_geolocation(ip: Optional[str]) -> dict:
    """
    Get geolocation information for an IP address.
    """

    if not ip:
        return {
            "status": "failed",
            "message": "No originating IP found."
        }

    url = f"{IP_API_URL}/{ip}"

    fields = (
        "status,country,regionName,city,"
        "lat,lon,isp,query"
    )

    try:
        response = requests.get(
            url,
            params={"fields": fields},
            timeout=5
        )

        response.raise_for_status()

        data = response.json()

        if data.get("status") != "success":
            return {
                "status": "failed",
                "message": "IP geolocation failed.",
                "ip": ip
            }

        return {
            "status": "success",
            "ip": data.get("query"),
            "country": data.get("country"),
            "region": data.get("regionName"),
            "city": data.get("city"),
            "latitude": data.get("lat"),
            "longitude": data.get("lon"),
            "isp": data.get("isp")
        }

    except requests.RequestException as error:
        return {
            "status": "failed",
            "message": f"Geolocation request failed: {error}",
            "ip": ip
        }


if __name__ == "__main__":
    # Simple test
    test_ip = "8.8.8.8"

    result = get_geolocation(test_ip)

    print(result)