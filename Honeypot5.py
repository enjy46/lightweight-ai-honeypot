import socket
import threading
import datetime
import hashlib
import os
import requests
import time
import joblib
import pandas as pd
import pefile
import logging
from collections import defaultdict
from threading import Thread
from scapy.all import sniff, IP, TCP, ICMP
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


# How logs are printed: date- info / warning / error - message( like a file detected)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)



# Honeypot decoy services
FAKE_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    80: "HTTP",
    443: "HTTPS",
    3389: "RDP",
    8080: "PROXY"
}

FAKE_BANNERS = {
    "FTP": b"220 Fake FTP Server ready\r\n",
    "SSH": b"SSH-2.0-OpenSSH_8.9p1\r\n",
    "HTTP": b"HTTP/1.1 200 OK\r\nServer: Apache\r\n\r\n",
    "HTTPS": b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n",
}








# Honeypot decoy functions
def create_fake_service(port, service_name):
    def handle_client(client_socket, address):
        src_ip = address[0]
        logging.warning(f"Decoy triggered: Attacker {src_ip} connected to fake {service_name} on port {port}")
        
        banner = FAKE_BANNERS.get(service_name, b"Welcome\r\n")
        try:
            client_socket.send(banner)
        except:
            pass
        
        current_time = datetime.datetime.now()
        key = (src_ip, port, service_name, 'DECOY')
        if not attack_details[key]['start_time']:
            attack_details[key]['start_time'] = current_time
        attack_details[key]['packet_count'] += 1
        client_socket.close()
    
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('0.0.0.0', port))
        server.listen(10)
        logging.info(f"Honeypot decoy: Fake {service_name} on port {port}")
        
        while True:
            client, addr = server.accept()
            Thread(target=handle_client, args=(client, addr), daemon=True).start()
    except Exception as e:
        logging.error(f"Failed to start decoy on port {port}: {e}")

def start_honeypot_decoys():
    logging.info("Starting honeypot decoy services...")
    for port, name in FAKE_SERVICES.items():
        Thread(target=create_fake_service, args=(port, name), daemon=True).start()
        time.sleep(0.1)
    logging.info(f"{len(FAKE_SERVICES)} decoy services active")









# Configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "malware_detector_model_final.pkl")
DOWNLOADS_DIR = os.path.join(BASE_DIR, "monitored")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")  # Replace with your actual key

# Thresholds
#If the ICMP ≥ 10 ICMP requests,  will be flagged as possible ICMP flood attack. Used for ping + too many = possible flood attack (DOS)
#If an IP sends ≥50 SYN packets, flag as SYN flood flagged as possible flood attack\
#Only trust ML detection if confidence ≥ 70%
ICMP_FLOOD_THRESHOLD = 3
SYN_FLOOD_THRESHOLD = 10
ML_CONFIDENCE_THRESHOLD = 0.7


checked_files = set()
malware_detections = []
tcp_connections = defaultdict(int) # dictionary that stores counts of TCP connections per IP
icmp_requests = defaultdict(int)
syn_counts = defaultdict(int)
attack_details = defaultdict(lambda: {'start_time': None, 'packet_count': 0}) #For every detected attack, you store when it started and how many packets were sent

# Load ML Model
# Define a function to load your trained ML model from file
def load_model():
    try:
        model_bundle = joblib.load(MODEL_PATH)
        
        model = model_bundle["model"]
        features = model_bundle["features"]
        scaler = model_bundle["scaler"]  # No selector!

        logging.info(f"✓ ML Model loaded: {len(features)} features")
        return model, features, scaler  # Only 3 things
    except Exception as e:
        logging.error(f"Failed to load model: {e}")
        return None, None, None
    

    
ml_model, ml_features, ml_scaler = load_model()


def extract_features(file_path):
    try:
        pe = pefile.PE(file_path)
        opt = pe.OPTIONAL_HEADER
        dos = pe.DOS_HEADER
        
        # calculate function count here, instead of using a placeholder value
        function_count = 0
        
        # Count exported functions (functions the file gives to other programs)
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            if pe.DIRECTORY_ENTRY_EXPORT.symbols:
                function_count += len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
        
        # Count imported functions (functions the file needs from Windows)
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                if hasattr(entry, 'imports'):
                    function_count += len(entry.imports)
        
        features = {
            "Minor_Linker_Version": opt.MinorLinkerVersion,
            "Major_OS_Version": opt.MajorOperatingSystemVersion,
            "Major_Subsystem_Version": opt.MajorSubsystemVersion,
            "Major_Image_Version": opt.MajorImageVersion,
            "Major_Linker_Version": opt.MajorLinkerVersion,
            "DLL_Characteristics": opt.DllCharacteristics,
            "e_res2": dos.e_res2[0] if hasattr(dos, 'e_res2') and dos.e_res2 else 0,
            "e_lfanew": dos.e_lfanew,
            "Subsystem": opt.Subsystem,
            "e_res": dos.e_res[0] if hasattr(dos, 'e_res') and dos.e_res else 0,
            "Section_count": len(pe.sections),
            "Magic": opt.Magic,
            "Size_of_Initialized_Data": opt.SizeOfInitializedData,
            "Size_of_Code": opt.SizeOfCode,
            "Number_of_Rva_and_Sizes": opt.NumberOfRvaAndSizes,
            "Function_count": function_count,  # ← USE THE REAL CALCULATED VALUE
        }
        
        return pd.DataFrame([features])
        
    except Exception as e:
        logging.error(f"Feature extraction error: {e}")
        return None

def predict_file(file_path):
    # Check PE file
    try:
        with open(file_path, 'rb') as f:
            if f.read(2) != b'MZ':
                return ("NOT_PE_FILE", 0)
    except:
        return ("ERROR", 0)

    features = extract_features(file_path)
    if features is None:
        return ("EXTRACTION_FAILED", 0)

    try:
        # Ensure correct order
        features = features[ml_features]

        # Apply scaler
        if ml_scaler:
            features = ml_scaler.transform(features)


        # Predict
        prediction = ml_model.predict(features)[0]
        probabilities = ml_model.predict_proba(features)[0]

        confidence = probabilities[1] if prediction == 1 else probabilities[0]
        result = "MALWARE" if prediction == 1 else "BENIGN"

        if result == "MALWARE" and confidence > ML_CONFIDENCE_THRESHOLD:
            logging.warning(f" MALWARE DETECTED: {os.path.basename(file_path)} ({confidence:.2%})")

        return (result, confidence)

    except Exception as e:
        logging.error(f"Prediction error: {e}")
        return ("ERROR", 0)



# Handles network packets
# Network Attack Detection

def packet_handler(packet):
    if not packet.haslayer(IP): # if the packet has no IP, we ignore it
        return
    

    # Prevents memory from filling up with old data
    # Initialize cleanup timer
    if not hasattr(packet_handler, 'last_cleanup'):
        packet_handler.last_cleanup = time.time()
    

    # Clean up SYN counts every 60 seconds
    if time.time() - packet_handler.last_cleanup > 60:
        for ip in list(syn_counts.keys()):
            syn_counts[ip] = max(0, syn_counts[ip] - 10)
            #If count reaches 0, remove IP from dictionary
            if syn_counts[ip] == 0:
                del syn_counts[ip]
        packet_handler.last_cleanup = time.time()
    
    current_time = datetime.datetime.now()
    src_ip = packet[IP].src
    
    #Check if packet has TCP layer. Extract destination port.
    if packet.haslayer(TCP):
        dst_port = packet[TCP].dport
        

        # SYN flood detection
        if packet[TCP].flags == 'S':
            syn_counts[src_ip] += 1
            if syn_counts[src_ip] > SYN_FLOOD_THRESHOLD:
                logging.warning(f" SYN flood from {src_ip}: {syn_counts[src_ip]} SYN packets")
                key = (src_ip, dst_port, 'SYN_FLOOD', 'SYN')
                if not attack_details[key]['start_time']:
                    attack_details[key]['start_time'] = current_time
                attack_details[key]['packet_count'] = syn_counts[src_ip]
        
        # Service detection
        # Service detection
        service_map = {21: 'FTP', 22: 'SSH', 23: 'TELNET', 80: 'HTTP', 443: 'HTTPS', 3389: 'RDP', 8080: 'PROXY'}
        service = service_map.get(dst_port, 'TCP')
        flag = "SYN" if packet[TCP].flags == 'S' else "Other"
        
        # ADD LIVE WARNING FOR SERVICE ATTACKS
        if service in ['FTP', 'SSH', 'HTTP', 'HTTPS'] and packet[TCP].flags == 'S':
            logging.warning(f" {service} connection attempt from {src_ip} to port {dst_port}")
        
        key = (src_ip, dst_port, service, flag)
        if not attack_details[key]['start_time']:
            attack_details[key]['start_time'] = current_time
        attack_details[key]['packet_count'] += 1

        
    elif packet.haslayer(ICMP) and packet[ICMP].type == 8:
        icmp_requests[src_ip] += 1
        key = (src_ip, 'ICMP', 'Echo_Request', 'N/A')
        
        if not attack_details[key]['start_time']:
            attack_details[key]['start_time'] = current_time
        attack_details[key]['packet_count'] += 1
        
        if icmp_requests[src_ip] >= ICMP_FLOOD_THRESHOLD:
            logging.warning(f" ICMP flood from {src_ip}: {icmp_requests[src_ip]} packets")

def generate_md5_hash(file_path):
    try:
        hash_md5 = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""): # Read file in chunks of 4096 bytes
                hash_md5.update(chunk) # Update hash with each chunk
        return hash_md5.hexdigest()
    except Exception as e:
        logging.error(f"MD5 generation failed: {e}")
        return None

def safe_generate_md5(file_path, retries=5, delay=1):
    for i in range(retries):
        try:
            hash_md5 = hashlib.md5()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except Exception:
            time.sleep(delay)
    logging.error(f"MD5 failed after retries: {file_path}")
    return None        

# Query VirusTotal database to see if file is known malware
# If not, skip VirusTotal check
def check_file_virustotal(md5_hash):
    """Check file with VirusTotal API"""
    if not md5_hash or VIRUSTOTAL_API_KEY == 'your_api_key_here':
        return None
    
    try:
        url = f'https://www.virustotal.com/api/v3/files/{md5_hash}'
        headers = {'x-apikey': VIRUSTOTAL_API_KEY}
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            result = response.json()
            stats = result['data']['attributes']['last_analysis_stats']
            return stats.get('malicious', 0)
        elif response.status_code == 404:
            return 0  # File not in VirusTotal database
        else:
            return None
    except Exception as e:
        logging.debug(f"VirusTotal error: {e}")
        return None

# Monitors Downloads folder for new files
class DownloadHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            return
        
        file_path = event.src_path
        if file_path in checked_files:
            return
        
        # testing this line
        # wait until file is fully written
        time.sleep(2)

        logging.info(f" New file: {os.path.basename(file_path)}")
        
        # Generate MD5
        md5 = safe_generate_md5(file_path)
        if md5:
            logging.info(f"MD5: {md5}")
        
        # VirusTotal check
        vt_result = check_file_virustotal(md5) if md5 else None
        if vt_result is not None:
            if vt_result > 0:
                logging.warning(f" VirusTotal: {vt_result} detections")
            else:
                logging.info(f" VirusTotal: Clean")
        
        # ML Detection
        ml_result = predict_file(file_path)
        logging.info(f" ML: {ml_result[0]} ({ml_result[1]:.2%})")
        
        # Store detection
        malware_detections.append((file_path, md5, vt_result, ml_result))
        checked_files.add(file_path)
        
        # Alert if threat detected
        if (vt_result and vt_result > 0) or (ml_result[0] == "MALWARE" and ml_result[1] > ML_CONFIDENCE_THRESHOLD):
            logging.warning(f" THREAT DETECTED: {os.path.basename(file_path)}")

def generate_report():
    # Generate final report
    print("SECURITY REPORT")
    
    print("\n ATTACKS DETECTED:")
    for key, details in attack_details.items():
        src_ip, port, protocol, flag = key
        if details['packet_count'] > 0:
            print(f"  {protocol} attack from {src_ip}:{port} - {details['packet_count']} packets")
    
    print("\n MALWARE SCANS:")
    for file_path, md5, vt, ml in malware_detections:
        filename = os.path.basename(file_path)
        print(f"\n  File: {filename}")
        if vt is not None:
            print(f"    VirusTotal: {vt} detections")
        print(f"    ML: {ml[0]} ({ml[1]:.2%})")
    
    print()  


def main():
    print("Honeypot - ML Powered Security Deception System")
    print()

    if ml_model is not None:
        print(f"ML Model: Active ({len(ml_features)} features)")
    else:
        print("ML Model: Not loaded")

    print(f"Decoy services: {len(FAKE_SERVICES)}")
    print(f"Monitoring Directory: {DOWNLOADS_DIR}")
    print(f"Thresholds: ICMP={ICMP_FLOOD_THRESHOLD}, SYN={SYN_FLOOD_THRESHOLD}")
    print()

    # Start honeypot decoys
    start_honeypot_decoys()

    # Start network monitoring thread
    network_thread = Thread(target=lambda: sniff(iface="Ethernet", prn=packet_handler, store=False), daemon=True)
    network_thread.start()
    logging.info("Network monitoring started")

    # Start file monitoring
    observer = Observer()
    observer.schedule(DownloadHandler(), DOWNLOADS_DIR, recursive=False)
    observer.start()
    logging.info(f"File monitoring started: {DOWNLOADS_DIR}")

    try:
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        print("\nShutting down...")
        observer.stop()
    finally:
        observer.join()
        generate_report()
        logging.info("Honeypot shutdown complete")

if __name__ == "__main__":
    main()
