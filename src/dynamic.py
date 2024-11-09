import os
import time
import requests

# Set your VirusTotal API key here
API_KEY ="4bd6e81b78df195e9c11a579fb8cf4ba84b27e9cf209dfccb996cae4578ab0d6"

# VirusTotal API URLs
VIRUSTOTAL_URL_SCAN = "https://www.virustotal.com/api/v3/files"
VIRUSTOTAL_URL_REPORT = "https://www.virustotal.com/api/v3/analyses/"

def upload_file_to_virustotal(filepath):
    headers = {"x-apikey": API_KEY}
    files = {"file": (os.path.basename(filepath), open(filepath, "rb"))}

    print(f"Uploading {filepath} for analysis...")
    print("THis may tack some time...")
    response = requests.post(VIRUSTOTAL_URL_SCAN, headers=headers, files=files)
    response_data = response.json()

    if response.status_code == 200:
        analysis_id = response_data["data"]["id"]
        print("File successfully uploaded.")
        return analysis_id
    else:
        print("Failed to upload file:", response_data)
        return None

def check_analysis_status(analysis_id):
    headers = {"x-apikey": API_KEY}
    print("Checking analysis status...")

    while True:
        response = requests.get(VIRUSTOTAL_URL_REPORT + analysis_id, headers=headers)
        response_data = response.json()

        # Check if analysis is done
        status = response_data["data"]["attributes"]["status"]
        if status == "completed":
            print("Analysis complete!")
            return response_data
        else:
            print("Analysis in progress, waiting for results...")
            time.sleep(10)  # Wait 10 seconds before checking again

def display_results(response_data):
    print("\n--- Analysis Summary ---")
    stats = response_data["data"]["attributes"]["stats"]
    print(f"Malicious detections: {stats['malicious']}")
    print(f"Harmless detections: {stats['harmless']}")

    print("\n--- Detailed Engine Results ---")
    for engine, result in response_data["data"]["attributes"]["results"].items():
        print(f"{engine}: {result['category']}")

if __name__ == "__main__":
    file_path = input("Give Path to the EXE: ")  # Replace with the path to your file
    analysis_id = upload_file_to_virustotal(file_path)

    if analysis_id:
        # Get and display results
        analysis_results = check_analysis_status(analysis_id)
        display_results(analysis_results)
