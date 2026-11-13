import requests
import random

API_URL = "http://127.0.0.1:8000/api/traffic/"

# Generate a unique test source IP for each simulator run
SOURCE_IP = f"10.255.{random.randint(1, 254)}.{random.randint(1, 254)}"

DESTINATION_IP = "192.168.1.1"


def send_traffic(destination_port):
    traffic_data = {
        "source_ip": SOURCE_IP,
        "destination_ip": DESTINATION_IP,
        "protocol": "TCP",
        "source_port": random.randint(49152, 65535),
        "destination_port": destination_port,
        "packet_size": random.randint(64, 1500)
    }

    response = requests.post(
        API_URL,
        json=traffic_data,
        timeout=10
    )

    response.raise_for_status()

    return response.json()


def simulate_normal_traffic():
    print("\nGenerating normal traffic...")

    result = None

    for _ in range(5):
        result = send_traffic(443)

    print("Normal traffic generated successfully!")
    return result


def simulate_port_scan():
    print("\nSimulating a port scan...")

    result = None

    for port in range(20, 30):
        result = send_traffic(port)

    print("Port scan simulation completed!")
    return result


def simulate_traffic_spike():
    print("\nSimulating a traffic spike...")

    result = None

    for i in range(100):
        result = send_traffic(443)

        if (i + 1) % 20 == 0:
            print(f"Sent {i + 1}/100 requests")

    print("Traffic spike simulation completed!")
    return result


def display_result(result):
    print("\n========== SENTINELX RESULTS ==========")

    print("\nSource IP:", SOURCE_IP)

    detections = result.get("detections", {})

    print("\nPort Scan Detection:")
    print(detections.get("port_scan"))

    print("\nTraffic Spike Detection:")
    print(detections.get("traffic_spike"))

    print("\nGenerated Alerts:")
    alerts = result.get("alerts", [])

    if alerts:
        for alert in alerts:
            print(alert)
    else:
        print("No security alerts generated.")

    print("\n=======================================")


def main():
    print("\n================================")
    print("       SENTINELX SIMULATOR")
    print("================================")
    print("1. Normal Traffic")
    print("2. Port Scan Simulation")
    print("3. Traffic Spike Simulation")
    print("================================")

    choice = input("Select simulation mode (1-3): ")

    try:
        if choice == "1":
            result = simulate_normal_traffic()

        elif choice == "2":
            result = simulate_port_scan()

        elif choice == "3":
            result = simulate_traffic_spike()

        else:
            print("Invalid selection.")
            return

        display_result(result)

    except requests.exceptions.RequestException as error:
        print("\nError connecting to SentinelX API.")
        print("Make sure the FastAPI server is running.")
        print("Details:", error)


if __name__ == "__main__":
    main()