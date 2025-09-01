import pyshark
import pandas as pd
import csv
from collections import defaultdict
import sys
import re

def extract_sip_rtp_ips_from_pcap(pcap_file):
    """
    Extract SIP and RTP IP addresses from UDP packets in pcap file
    """
    print(f"Analyzing pcap file: {pcap_file}")
    
    sip_ips = defaultdict(int)
    rtp_ips = defaultdict(int)
    all_detected_ips = set()
    
    try:
        # Capture both SIP and RTP traffic
        capture = pyshark.FileCapture(pcap_file, display_filter='udp')
        
        packet_count = 0
        for packet in capture:
            packet_count += 1
            try:
                if hasattr(packet, 'ip'):
                    src_ip = packet.ip.src
                    dst_ip = packet.ip.dst
                    
                    # Check for SIP traffic (usually port 5060)
                    if hasattr(packet, 'udp'):
                        src_port = packet.udp.srcport
                        dst_port = packet.udp.dstport
                        
                        # SIP detection (port 5060)
                        if '5060' in [src_port, dst_port] and hasattr(packet, 'sip'):
                            sip_ips[src_ip] += 1
                            sip_ips[dst_ip] += 1
                            all_detected_ips.update([src_ip, dst_ip])
                            
                            # Extract additional SIP information
                            if hasattr(packet.sip, 'from_host'):
                                caller_ip = packet.sip.from_host
                                sip_ips[caller_ip] += 1
                                all_detected_ips.add(caller_ip)
                            
                            if hasattr(packet.sip, 'to_host'):
                                callee_ip = packet.sip.to_host
                                sip_ips[callee_ip] += 1
                                all_detected_ips.add(callee_ip)
                        
                        # RTP detection (ports 10000-20000 typically)
                        elif int(src_port) >= 10000 and int(src_port) <= 20000:
                            rtp_ips[src_ip] += 1
                            rtp_ips[dst_ip] += 1
                            all_detected_ips.update([src_ip, dst_ip])
                            
            except AttributeError as e:
                continue
            except Exception as e:
                print(f"Error processing packet {packet_count}: {e}")
                continue
                
    except Exception as e:
        print(f"Error reading pcap file: {e}")
        return set(), {}, {}
    
    print(f"Processed {packet_count} UDP packets")
    print(f"Found {len(sip_ips)} SIP-related IP addresses")
    print(f"Found {len(rtp_ips)} RTP-related IP addresses")
    print(f"Total unique IPs detected: {len(all_detected_ips)}")
    
    return all_detected_ips, sip_ips, rtp_ips

def load_blacklisted_ips(csv_file):
    """
    Load blacklisted IPs from CSV file
    """
    blacklisted_ips = set()
    
    try:
        # Try to read with pandas first
        try:
            df = pd.read_csv(csv_file)
            if 'ip_address' in df.columns:
                blacklisted_ips = set(df['ip_address'].dropna().tolist())
            else:
                # If no header, assume first column contains IPs
                blacklisted_ips = set(df.iloc[:, 0].dropna().tolist())
        except:
            # Fallback to manual CSV reading
            with open(csv_file, 'r', encoding='utf-8') as f:
                reader = csv.reader(f)
                for row in reader:
                    if row and row[0].strip():  # Check if row is not empty
                        # Extract IP using regex to handle various formats
                        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', row[0])
                        if ip_match:
                            blacklisted_ips.add(ip_match.group(0))
    
    except Exception as e:
        print(f"Error reading blacklist CSV: {e}")
        return set()
    
    print(f"Loaded {len(blacklisted_ips)} blacklisted IPs")
    return blacklisted_ips

def check_for_blacklisted_ips(detected_ips, blacklisted_ips, sip_ips, rtp_ips):
    """
    Check if any detected IPs are in the blacklist
    """
    matches = detected_ips.intersection(blacklisted_ips)
    
    if matches:
        print("\n🚨 ALERT: BLACKLISTED IPS DETECTED! 🚨")
        print("=" * 60)
        
        for ip in matches:
            sip_count = sip_ips.get(ip, 0)
            rtp_count = rtp_ips.get(ip, 0)
            total_packets = sip_count + rtp_count
            
            print(f"BLACKLISTED IP: {ip}")
            print(f"  - SIP Packets: {sip_count}")
            print(f"  - RTP Packets: {rtp_count}")
            print(f"  - Total Packets: {total_packets}")
            
            if sip_count > 0:
                print(f"  - Role: SIP Participant")
            elif rtp_count > 0:
                print(f"  - Role: RTP Media Stream")
            else:
                print(f"  - Role: General UDP Traffic")
            
            print(f"  - Threat Level: CRITICAL")
            print("-" * 40)
            
        return True, matches
    else:
        print("\n✅ No blacklisted IPs detected in the traffic")
        return False, set()

def generate_detailed_report(detected_ips, sip_ips, rtp_ips, blacklisted_ips, matches):
    """
    Generate a detailed security report
    """
    print("\n📊 DETAILED SECURITY REPORT")
    print("=" * 50)
    print(f"Total IPs detected: {len(detected_ips)}")
    print(f"SIP-related IPs: {len(sip_ips)}")
    print(f"RTP-related IPs: {len(rtp_ips)}")
    print(f"Blacklisted IPs in database: {len(blacklisted_ips)}")
    print(f"Blacklisted IPs detected: {len(matches)}")
    
    if matches:
        print("\n🔴 SECURITY ALERT SUMMARY:")
        print("Immediate action required for the following threats:")
        for ip in matches:
            print(f"  - {ip} (SIP: {sip_ips.get(ip,0)}, RTP: {rtp_ips.get(ip,0)})")
        
        print("\nRecommended actions:")
        print("1. Block these IPs at firewall level")
        print("2. Investigate call logs involving these IPs")
        print("3. Check for any unauthorized access attempts")
        print("4. Review SIP authentication mechanisms")
    else:
        print("\n🟢 Security status: Normal - No threats detected")

def main():
    # File paths
    pcap_file = "call1.pcap"  # Change to your pcap file path
    blacklist_file = "Blacklisted ip.csv"  # Your blacklist CSV file
    
    print("SIP/RTP Security Scanner")
    print("=" * 30)
    
    # Load blacklisted IPs
    blacklisted_ips = load_blacklisted_ips(blacklist_file)
    if not blacklisted_ips:
        print("Warning: No blacklisted IPs loaded. Continuing with analysis...")
    
    # Extract IPs from pcap (SIP and RTP)
    detected_ips, sip_ips, rtp_ips = extract_sip_rtp_ips_from_pcap(pcap_file)
    if not detected_ips:
        print("No IPs found in pcap file. Exiting.")
        return
    
    # Check for matches
    alert_triggered, matched_ips = check_for_blacklisted_ips(
        detected_ips, blacklisted_ips, sip_ips, rtp_ips
    )
    
    # Generate detailed report
    generate_detailed_report(detected_ips, sip_ips, rtp_ips, blacklisted_ips, matched_ips)
    
    # Save results to file
    try:
        with open('security_scan_results.txt', 'w') as f:
            f.write("SIP/RTP Security Scan Results\n")
            f.write("=" * 40 + "\n")
            f.write(f"PCAP File: {pcap_file}\n")
            f.write(f"Total IPs detected: {len(detected_ips)}\n")
            f.write(f"Blacklisted IPs detected: {len(matched_ips)}\n")
            if matched_ips:
                f.write("\nBLACKLISTED IPS FOUND:\n")
                for ip in matched_ips:
                    f.write(f"{ip} (SIP: {sip_ips.get(ip,0)}, RTP: {rtp_ips.get(ip,0)})\n")
        print("\n📝 Results saved to 'security_scan_results.txt'")
    except Exception as e:
        print(f"Warning: Could not save results to file: {e}")

if __name__ == "__main__":
    main()
