import pandas as pd
import joblib
from scapy.all import sniff, IP, TCP, UDP
import time
import numpy as np
from datetime import datetime

# Your 20 selected features
selected_features = [
    'PSH Flag Count', 'Destination Port', 'Avg Bwd Segment Size', 'min_seg_size_forward',
    'Init_Win_bytes_forward', 'Bwd Packet Length Mean', 'Packet Length Mean',
    'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd IAT Max',
    'ACK Flag Count', 'Packet Length Std', 'Average Packet Size',
    'Bwd Packet Length Std', 'Packet Length Variance', 'Idle Max',
    'Flow IAT Max', 'Idle Mean', 'Idle Min', 'Max Packet Length'
]

# Load model and scaler using joblib
try:
    print("Loading model and scaler...")
    model = joblib.load('random_forest_model_features.pkl')
    scaler = joblib.load('scaler.pkl')
    print("Model and scaler loaded successfully!")
except Exception as e:
    print(f"Error loading model or scaler: {e}")
    exit(1)

# Stats tracking
stats = {
    'normal_packets': 0,
    'attack_packets': 0,
    'total_packets': 0,
    'start_time': time.time()
}

def extract_features(packet):
    # Handle only IP packets
    if not packet.haslayer(IP):
        return None

    try:
        features = {
            'PSH Flag Count': int(packet[TCP].flags & 0x08) if packet.haslayer(TCP) else 0,
            'Destination Port': packet[TCP].dport if packet.haslayer(TCP) else (packet[UDP].dport if packet.haslayer(UDP) else 0),
            'Avg Bwd Segment Size': 0,
            'min_seg_size_forward': 0,
            'Init_Win_bytes_forward': packet[TCP].window if packet.haslayer(TCP) else 0,
            'Bwd Packet Length Mean': 0,
            'Packet Length Mean': len(packet),
            'Fwd Packet Length Max': len(packet),
            'Fwd Packet Length Min': len(packet),
            'Fwd IAT Max': 0,
            'ACK Flag Count': int(packet[TCP].flags & 0x10) if packet.haslayer(TCP) else 0,
            'Packet Length Std': 0,
            'Average Packet Size': len(packet),
            'Bwd Packet Length Std': 0,
            'Packet Length Variance': 0,
            'Idle Max': 0,
            'Flow IAT Max': 0,
            'Idle Mean': 0,
            'Idle Min': 0,
            'Max Packet Length': len(packet)
        }
        return features
    except Exception as e:
        print(f"Error extracting features: {e}")
        return None

def packet_callback(packet):
    features = extract_features(packet)
    if features is None:
        return

    try:
        # Create DataFrame with feature names
        X_live = pd.DataFrame([features])
        
        # Ensure correct feature order
        X_live = X_live[selected_features]
        
        # Scale features
        X_scaled = scaler.transform(X_live)
        
        # Convert back to DataFrame with feature names to avoid the warning
        X_scaled_df = pd.DataFrame(X_scaled, columns=selected_features)
        
        # Make prediction
        prediction = model.predict(X_scaled_df)
        
        # Update stats
        stats['total_packets'] += 1
        if prediction[0] == 1:
            label = "⚠️ ATTACK DETECTED!"
            stats['attack_packets'] += 1
        else:
            label = "✅ Normal traffic"
            stats['normal_packets'] += 1
        
        # Add source and destination info if available
        src_info = f"src={packet[IP].src}" if packet.haslayer(IP) else ""
        dst_info = f"dst={packet[IP].dst}" if packet.haslayer(IP) else ""
        port_info = f"port={features['Destination Port']}" if features['Destination Port'] != 0 else ""
        
        # Print result with timestamp and packet info
        print(f"{datetime.now().strftime('%H:%M:%S')} - {label} {src_info} {dst_info} {port_info}")
        
        # Show stats every 100 packets
        if stats['total_packets'] % 100 == 0:
            elapsed = time.time() - stats['start_time']
            print(f"\n--- STATS after {stats['total_packets']} packets ({elapsed:.1f}s) ---")
            print(f"Normal: {stats['normal_packets']} ({stats['normal_packets']/stats['total_packets']*100:.1f}%)")
            print(f"Attack: {stats['attack_packets']} ({stats['attack_packets']/stats['total_packets']*100:.1f}%)")
            print("-------------------------------------------\n")
            
    except Exception as e:
        print(f"Error during prediction: {e}")

# Entry point
if __name__ == "__main__":
    print("🛡️ Real-time Network Intrusion Detection started")
    print("Press Ctrl+C to stop monitoring")
    print("-------------------------------------------")
    
    try:
        sniff(prn=packet_callback, store=0)
    except KeyboardInterrupt:
        elapsed = time.time() - stats['start_time']
        print("\n🛑 Monitoring stopped")
        print(f"Session duration: {elapsed:.1f} seconds")
        print(f"Total packets analyzed: {stats['total_packets']}")
        if stats['total_packets'] > 0:
            print(f"Normal packets: {stats['normal_packets']} ({stats['normal_packets']/stats['total_packets']*100:.1f}%)")
            print(f"Attack packets: {stats['attack_packets']} ({stats['attack_packets']/stats['total_packets']*100:.1f}%)")