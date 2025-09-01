#!/usr/bin/env python3
"""
VoIP Call Tracer - PCAP Analyzer
Analyzes PCAP files to extract VoIP call metadata from UDP packets
"""

import argparse
import csv
import re
import struct
import time
from collections import defaultdict, Counter
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Set
import statistics

try:
    from scapy.all import rdpcap, UDP, IP
    from scapy.packet import Packet
except ImportError:
    print("Error: scapy library is required. Install with: pip install scapy")
    exit(1)

class VoIPCallTracer:
    def __init__(self):
        self.calls = {}
        self.rtp_streams = defaultdict(list)
        self.sip_transactions = defaultdict(list)
        self.concurrent_calls_tracker = defaultdict(int)
        
        # SIP response codes mapping
        self.sip_response_codes = {
            100: "Trying", 180: "Ringing", 183: "Session Progress",
            200: "OK", 202: "Accepted", 
            400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
            404: "Not Found", 405: "Method Not Allowed", 408: "Request Timeout",
            480: "Temporarily Unavailable", 481: "Call/Transaction Does Not Exist",
            482: "Loop Detected", 483: "Too Many Hops", 486: "Busy Here",
            487: "Request Terminated", 488: "Not Acceptable Here",
            500: "Internal Server Error", 501: "Not Implemented",
            502: "Bad Gateway", 503: "Service Unavailable", 504: "Server Time-out",
            600: "Busy Everywhere", 603: "Decline", 604: "Does Not Exist Anywhere"
        }
        
        # RTP payload types for codec identification
        self.rtp_payload_types = {
            0: "G.711μ (PCMU)",
            8: "G.711A (PCMA)",
            3: "GSM",
            4: "G.723",
            5: "DVI4-8000",
            6: "DVI4-16000",
            7: "LPC",
            9: "G.722",
            10: "L16-2",
            11: "L16-1",
            12: "QCELP",
            13: "CN",
            14: "MPA",
            15: "G.728",
            16: "DVI4-11025",
            17: "DVI4-22050",
            18: "G.729"
        }

    def is_sip_packet(self, packet_data: bytes) -> bool:
        """Identify SIP packets by looking for SIP headers in UDP payload"""
        try:
            payload = packet_data.decode('utf-8', errors='ignore')
            sip_methods = ['INVITE', 'ACK', 'BYE', 'CANCEL', 'OPTIONS', 'REGISTER', 'INFO', 'PRACK', 'SUBSCRIBE', 'NOTIFY', 'UPDATE', 'MESSAGE', 'REFER']
            sip_responses = ['SIP/2.0']
            
            for method in sip_methods:
                if payload.startswith(method + ' '):
                    return True
            
            for response in sip_responses:
                if payload.startswith(response):
                    return True
                    
            return False
        except:
            return False

    def is_rtp_packet(self, packet_data: bytes, src_port: int, dst_port: int) -> bool:
        """Identify RTP packets by analyzing packet structure and port patterns"""
        if len(packet_data) < 12:  # RTP header minimum size
            return False
            
        # RTP typically uses even ports in range 10000-65534
        if not ((10000 <= src_port <= 65534 and src_port % 2 == 0) or 
                (10000 <= dst_port <= 65534 and dst_port % 2 == 0)):
            return False
            
        try:
            # Parse RTP header
            rtp_header = struct.unpack('!BBHII', packet_data[:12])
            version = (rtp_header[0] >> 6) & 0x3
            padding = (rtp_header[0] >> 5) & 0x1
            extension = (rtp_header[0] >> 4) & 0x1
            cc = rtp_header[0] & 0xF
            marker = (rtp_header[1] >> 7) & 0x1
            payload_type = rtp_header[1] & 0x7F
            
            # Check for valid RTP version (should be 2)
            if version != 2:
                return False
                
            # Check for reasonable payload type (0-127)
            if payload_type > 127:
                return False
                
            # Check packet length consistency
            expected_header_length = 12 + (cc * 4)
            if len(packet_data) < expected_header_length:
                return False
                
            return True
        except:
            return False

    def parse_sip_packet(self, packet_data: bytes, timestamp: float, src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> Dict:
        """Parse SIP packet and extract relevant information"""
        try:
            payload = packet_data.decode('utf-8', errors='ignore')
            lines = payload.split('\r\n')
            
            sip_info = {
                'timestamp': timestamp,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'method': None,
                'response_code': None,
                'call_id': None,
                'from_tag': None,
                'to_tag': None,
                'cseq': None,
                'contact': None,
                'content_type': None,
                'sdp_info': {}
            }
            
            # Parse first line
            first_line = lines[0] if lines else ""
            if first_line.startswith('SIP/2.0'):
                # Response
                parts = first_line.split(' ', 2)
                if len(parts) >= 2:
                    try:
                        sip_info['response_code'] = int(parts[1])
                    except:
                        pass
            else:
                # Request
                parts = first_line.split(' ')
                if parts:
                    sip_info['method'] = parts[0]
            
            # Parse headers
            in_sdp = False
            for line in lines[1:]:
                if line.strip() == "":
                    in_sdp = True
                    continue
                    
                if in_sdp:
                    # Parse SDP
                    if line.startswith('m='):
                        media_parts = line.split()
                        if len(media_parts) >= 4:
                            sip_info['sdp_info']['media_port'] = int(media_parts[1])
                            sip_info['sdp_info']['media_type'] = media_parts[0][2:]
                    elif line.startswith('a=rtpmap:'):
                        # Extract codec info
                        rtpmap_match = re.search(r'a=rtpmap:(\d+)\s+([^/]+)', line)
                        if rtpmap_match:
                            pt = int(rtpmap_match.group(1))
                            codec = rtpmap_match.group(2)
                            sip_info['sdp_info']['payload_type'] = pt
                            sip_info['sdp_info']['codec'] = codec
                    continue
                
                # Parse SIP headers
                if ':' in line:
                    header, value = line.split(':', 1)
                    header = header.strip().lower()
                    value = value.strip()
                    
                    if header == 'call-id':
                        sip_info['call_id'] = value
                    elif header == 'from' or header == 'f':
                        tag_match = re.search(r'tag=([^;]+)', value)
                        if tag_match:
                            sip_info['from_tag'] = tag_match.group(1)
                    elif header == 'to' or header == 't':
                        tag_match = re.search(r'tag=([^;]+)', value)
                        if tag_match:
                            sip_info['to_tag'] = tag_match.group(1)
                    elif header == 'cseq':
                        sip_info['cseq'] = value
                    elif header == 'contact' or header == 'm':
                        sip_info['contact'] = value
                    elif header == 'content-type' or header == 'c':
                        sip_info['content_type'] = value
            
            return sip_info
        except Exception as e:
            print(f"Error parsing SIP packet: {e}")
            return None

    def parse_rtp_packet(self, packet_data: bytes, timestamp: float, src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> Dict:
        """Parse RTP packet and extract relevant information"""
        try:
            if len(packet_data) < 12:
                return None
                
            # Parse RTP header
            rtp_header = struct.unpack('!BBHII', packet_data[:12])
            version = (rtp_header[0] >> 6) & 0x3
            padding = (rtp_header[0] >> 5) & 0x1
            extension = (rtp_header[0] >> 4) & 0x1
            cc = rtp_header[0] & 0xF
            marker = (rtp_header[1] >> 7) & 0x1
            payload_type = rtp_header[1] & 0x7F
            sequence_number = rtp_header[2]
            rtp_timestamp = rtp_header[3]
            ssrc = rtp_header[4]
            
            rtp_info = {
                'timestamp': timestamp,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'version': version,
                'payload_type': payload_type,
                'sequence_number': sequence_number,
                'rtp_timestamp': rtp_timestamp,
                'ssrc': ssrc,
                'marker': marker,
                'packet_size': len(packet_data),
                'payload_size': len(packet_data) - 12 - (cc * 4)
            }
            
            return rtp_info
        except Exception as e:
            print(f"Error parsing RTP packet: {e}")
            return None

    def detect_silence(self, payload: bytes) -> bool:
        """Simple silence detection based on payload analysis"""
        if len(payload) < 10:
            return True
            
        # For G.711, silence is often represented by repeated values or very low amplitude
        try:
            # Check for repeated bytes (common in silence)
            unique_bytes = len(set(payload[:20]))  # Check first 20 bytes
            if unique_bytes <= 2:
                return True
                
            # Check for low amplitude (for G.711 μ-law, silence is around 0xFF or 0x7F)
            silence_patterns = [0xFF, 0x7F, 0x00]
            silence_count = sum(1 for byte in payload[:20] if byte in silence_patterns)
            if silence_count > len(payload[:20]) * 0.8:
                return True
                
            return False
        except:
            return False

    def calculate_jitter(self, packets: List[Dict]) -> Tuple[float, float]:
        """Calculate average jitter and jitter variance for RTP stream in milliseconds"""
        if len(packets) < 3:
            return 0.0, 0.0
            
        jitter_values = []
        prev_arrival_time = None
        prev_rtp_timestamp = None
        prev_transit = None
        
        # Determine sample rate based on payload type
        sample_rates = {0: 8000, 8: 8000, 9: 8000, 18: 8000}  # Common codecs
        payload_type = packets[0]['payload_type'] if packets else 0
        sample_rate = sample_rates.get(payload_type, 8000)  # Default to 8kHz
        
        for packet in packets:
            arrival_time = packet['timestamp']
            rtp_timestamp = packet['rtp_timestamp']
            
            if prev_arrival_time is not None and prev_rtp_timestamp is not None:
                # Calculate arrival time difference in seconds
                arrival_diff = arrival_time - prev_arrival_time
                
                # Calculate RTP timestamp difference and convert to seconds
                rtp_diff = rtp_timestamp - prev_rtp_timestamp
                
                # Handle RTP timestamp wraparound (32-bit)
                if rtp_diff < 0:
                    rtp_diff += 2**32
                    
                rtp_time_seconds = rtp_diff / sample_rate
                
                # Calculate transit time
                transit = arrival_diff - rtp_time_seconds
                
                # Calculate jitter from transit time variations
                if prev_transit is not None:
                    jitter_ms = abs(transit - prev_transit) * 1000  # Convert to milliseconds
                    jitter_values.append(jitter_ms)
                
                prev_transit = transit
            
            prev_arrival_time = arrival_time
            prev_rtp_timestamp = rtp_timestamp
        
        if not jitter_values:
            return 0.0, 0.0
            
        # Remove outliers (values > 1 second are likely calculation errors)
        filtered_jitter = [j for j in jitter_values if j < 1000]
        
        if not filtered_jitter:
            return 0.0, 0.0
            
        avg_jitter = statistics.mean(filtered_jitter)
        jitter_variance = statistics.variance(filtered_jitter) if len(filtered_jitter) > 1 else 0.0
        
        return round(avg_jitter, 3), round(jitter_variance, 3)

    def calculate_packet_loss(self, packets: List[Dict]) -> float:
        """Calculate packet loss percentage based on sequence numbers"""
        if len(packets) < 2:
            return 0.0
            
        sequence_numbers = [p['sequence_number'] for p in packets]
        sequence_numbers.sort()
        
        if not sequence_numbers:
            return 0.0
            
        expected_packets = sequence_numbers[-1] - sequence_numbers[0] + 1
        actual_packets = len(sequence_numbers)
        
        # Account for sequence number wraparound
        if expected_packets > 65536:
            expected_packets = actual_packets
            
        if expected_packets <= 0:
            return 0.0
            
        loss_percentage = ((expected_packets - actual_packets) / expected_packets) * 100
        return max(0.0, min(100.0, loss_percentage))

    def analyze_pcap(self, pcap_file: str) -> List[Dict]:
        """Main analysis function"""
        print(f"Loading PCAP file: {pcap_file}")
        
        try:
            packets = rdpcap(pcap_file)
        except Exception as e:
            print(f"Error reading PCAP file: {e}")
            return []
            
        print(f"Loaded {len(packets)} packets")
        
        sip_packets = []
        rtp_packets = defaultdict(list)
        call_sessions = defaultdict(dict)
        
        # First pass: classify packets
        for packet in packets:
            if not (packet.haslayer(UDP) and packet.haslayer(IP)):
                continue
                
            udp_layer = packet[UDP]
            ip_layer = packet[IP]
            
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            src_port = udp_layer.sport
            dst_port = udp_layer.dport
            timestamp = float(packet.time)
            
            payload = bytes(udp_layer.payload)
            
            if self.is_sip_packet(payload):
                sip_info = self.parse_sip_packet(payload, timestamp, src_ip, dst_ip, src_port, dst_port)
                if sip_info:
                    sip_packets.append(sip_info)
                    
            elif self.is_rtp_packet(payload, src_port, dst_port):
                rtp_info = self.parse_rtp_packet(payload, timestamp, src_ip, dst_ip, src_port, dst_port)
                if rtp_info:
                    # Group RTP packets by stream (SSRC + IP pair)
                    stream_key = f"{src_ip}:{dst_ip}:{rtp_info['ssrc']}"
                    rtp_packets[stream_key].append(rtp_info)
        
        print(f"Found {len(sip_packets)} SIP packets and {sum(len(stream) for stream in rtp_packets.values())} RTP packets")
        
        # Second pass: correlate SIP and RTP to build call sessions
        calls = []
        call_id_to_streams = defaultdict(list)
        
        # Process SIP packets to build call flows
        sip_calls = defaultdict(list)
        for sip in sip_packets:
            if sip['call_id']:
                sip_calls[sip['call_id']].append(sip)
        
        # If we have SIP packets, analyze normal call sessions
        if sip_calls:
            for call_id, sip_msgs in sip_calls.items():
                if not sip_msgs:
                    continue
                    
                call_info = self.analyze_call_session(call_id, sip_msgs, rtp_packets)
                if call_info:
                    calls.append(call_info)
        
        # If no SIP packets but we have RTP streams, create synthetic call sessions
        elif rtp_packets:
            print("No SIP packets found, analyzing RTP-only streams...")
            calls = self.analyze_rtp_only_streams(rtp_packets)
        
        return calls

    def analyze_call_session(self, call_id: str, sip_msgs: List[Dict], rtp_streams: Dict) -> Dict:
        """Analyze a single call session"""
        sip_msgs.sort(key=lambda x: x['timestamp'])
        
        call_info = {
            'call_id': call_id,
            'caller_ip': None,
            'callee_ip': None,
            'start_time': None,
            'end_time': None,
            'call_duration': 0,
            'setup_time': 0,
            'response_code_variety': set(),
            'call_termination_method': 0,  # 0=normal, 1=timeout, 2=error
            'avg_jitter': 0,
            'jitter_variance': 0,
            'packet_loss_percent': 0,
            'codec_type': 'Unknown',
            'packets_per_second': 0,
            'bytes_per_second': 0,
            'retransmission_count': 0,
            'concurrent_calls': 0,
            'peak_bandwidth': 0,
            'talk_silence_ratio': 0,
            'port_range_used': 0
        }
        
        # Find INVITE and corresponding responses
        invite_time = None
        ok_time = None
        bye_time = None
        media_ports = set()
        
        for msg in sip_msgs:
            # Track response codes
            if msg['response_code']:
                call_info['response_code_variety'].add(msg['response_code'])
                
                # Find 200 OK for setup time calculation
                if msg['response_code'] == 200 and invite_time:
                    ok_time = msg['timestamp']
                    
            # Find INVITE
            elif msg['method'] == 'INVITE':
                invite_time = msg['timestamp']
                call_info['start_time'] = datetime.fromtimestamp(msg['timestamp']).isoformat()
                call_info['caller_ip'] = msg['src_ip']
                call_info['callee_ip'] = msg['dst_ip']
                
                # Extract codec info from SDP
                if 'payload_type' in msg['sdp_info']:
                    pt = msg['sdp_info']['payload_type']
                    if pt in self.rtp_payload_types:
                        call_info['codec_type'] = f"{pt}={self.rtp_payload_types[pt]}"
                    else:
                        call_info['codec_type'] = f"{pt}=Unknown"
                        
                if 'media_port' in msg['sdp_info']:
                    media_ports.add(msg['media_port'])
                    
            # Find BYE
            elif msg['method'] == 'BYE':
                bye_time = msg['timestamp']
                call_info['end_time'] = datetime.fromtimestamp(msg['timestamp']).isoformat()
        
        # Calculate setup time
        if invite_time and ok_time:
            call_info['setup_time'] = int((ok_time - invite_time) * 1000)  # milliseconds
            
        # Calculate call duration
        if invite_time and bye_time:
            call_info['call_duration'] = int(bye_time - invite_time)
        elif invite_time and ok_time:
            # If no BYE found, use last RTP packet time
            last_rtp_time = invite_time
            for stream_packets in rtp_streams.values():
                if stream_packets:
                    stream_end = max(p['timestamp'] for p in stream_packets)
                    last_rtp_time = max(last_rtp_time, stream_end)
            call_info['call_duration'] = int(last_rtp_time - invite_time)
            
        # Determine termination method
        error_codes = [code for code in call_info['response_code_variety'] if 400 <= code < 700]
        if error_codes:
            call_info['call_termination_method'] = 2  # error
        elif bye_time:
            call_info['call_termination_method'] = 0  # normal
        else:
            call_info['call_termination_method'] = 1  # timeout
            
        # Find matching RTP streams
        matching_streams = []
        if call_info['caller_ip'] and call_info['callee_ip']:
            for stream_key, stream_packets in rtp_streams.items():
                if (call_info['caller_ip'] in stream_key or 
                    call_info['callee_ip'] in stream_key):
                    matching_streams.extend(stream_packets)
                    
        # Analyze RTP streams
        if matching_streams:
            matching_streams.sort(key=lambda x: x['timestamp'])
            
            # Calculate jitter
            call_info['avg_jitter'], call_info['jitter_variance'] = self.calculate_jitter(matching_streams)
            
            # Calculate packet loss
            call_info['packet_loss_percent'] = self.calculate_packet_loss(matching_streams)
            
            # Calculate bandwidth metrics
            total_bytes = sum(p['packet_size'] for p in matching_streams)
            total_packets = len(matching_streams)
            
            if call_info['call_duration'] > 0:
                call_info['packets_per_second'] = total_packets / call_info['call_duration']
                call_info['bytes_per_second'] = total_bytes / call_info['call_duration']
                
            # Calculate peak bandwidth (10-second windows)
            call_info['peak_bandwidth'] = self.calculate_peak_bandwidth(matching_streams)
            
            # Calculate talk/silence ratio
            call_info['talk_silence_ratio'] = self.calculate_talk_silence_ratio(matching_streams)
            
            # Calculate port range
            ports = set()
            for p in matching_streams:
                ports.add(p['src_port'])
                ports.add(p['dst_port'])
            call_info['port_range_used'] = max(ports) - min(ports) if len(ports) > 1 else 0
            
            # Simple retransmission detection (duplicate sequence numbers)
            seq_counts = Counter(p['sequence_number'] for p in matching_streams)
            call_info['retransmission_count'] = sum(count - 1 for count in seq_counts.values() if count > 1)
        
        # Convert response code variety to count
        call_info['response_code_variety'] = len(call_info['response_code_variety'])
        
        # TODO: Calculate concurrent calls (would need global analysis)
        call_info['concurrent_calls'] = 1  # Placeholder
        
        return call_info

    def calculate_peak_bandwidth(self, rtp_packets: List[Dict]) -> int:
        """Calculate peak bandwidth in bytes per second (10-second windows)"""
        if not rtp_packets:
            return 0
            
        # Group packets into 10-second windows
        windows = defaultdict(int)
        for packet in rtp_packets:
            window = int(packet['timestamp'] // 10) * 10
            windows[window] += packet['packet_size']
            
        # Convert to bytes per second (each window is 10 seconds)
        peak_bps = max(windows.values()) // 10 if windows else 0
        return peak_bps

    def analyze_rtp_only_streams(self, rtp_streams: Dict) -> List[Dict]:
        """Analyze RTP-only captures without SIP signaling"""
        calls = []
        
        print(f"Analyzing {len(rtp_streams)} RTP streams...")
        
        # Group streams by IP pairs to identify call sessions
        ip_pairs = defaultdict(list)
        for stream_key, stream_packets in rtp_streams.items():
            if not stream_packets:
                continue
                
            # Extract IP pair from first packet
            first_packet = stream_packets[0]
            src_ip = first_packet['src_ip']
            dst_ip = first_packet['dst_ip']
            
            # Create bidirectional key
            ip_pair = tuple(sorted([src_ip, dst_ip]))
            ip_pairs[ip_pair].extend(stream_packets)
        
        call_id = 1
        for ip_pair, all_packets in ip_pairs.items():
            if len(all_packets) < 10:  # Skip very short streams
                continue
                
            all_packets.sort(key=lambda x: x['timestamp'])
            
            # Create synthetic call info
            call_info = {
                'call_id': f"RTP_CALL_{call_id}",
                'caller_ip': ip_pair[0],
                'callee_ip': ip_pair[1],
                'start_time': datetime.fromtimestamp(all_packets[0]['timestamp']).isoformat(),
                'end_time': datetime.fromtimestamp(all_packets[-1]['timestamp']).isoformat(),
                'call_duration': int(all_packets[-1]['timestamp'] - all_packets[0]['timestamp']),
                'setup_time': 0,  # Unknown without SIP
                'response_code_variety': 0,  # No SIP responses
                'call_termination_method': 0,  # Assume normal
                'avg_jitter': 0,
                'jitter_variance': 0,
                'packet_loss_percent': 0,
                'codec_type': 'Unknown',
                'packets_per_second': 0,
                'bytes_per_second': 0,
                'retransmission_count': 0,
                'concurrent_calls': 1,
                'peak_bandwidth': 0,
                'talk_silence_ratio': 0,
                'port_range_used': 0
            }
            
            # Analyze the RTP stream
            self.analyze_rtp_stream_details(call_info, all_packets)
            calls.append(call_info)
            call_id += 1
            
        return calls

    def analyze_rtp_stream_details(self, call_info: Dict, rtp_packets: List[Dict]):
        """Analyze RTP stream details and populate call_info"""
        if not rtp_packets:
            return
            
        # Basic metrics
        total_bytes = sum(p['packet_size'] for p in rtp_packets)
        total_packets = len(rtp_packets)
        duration = call_info['call_duration']
        
        if duration > 0:
            call_info['packets_per_second'] = round(total_packets / duration, 2)
            call_info['bytes_per_second'] = round(total_bytes / duration, 2)
        
        # Calculate jitter
        call_info['avg_jitter'], call_info['jitter_variance'] = self.calculate_jitter(rtp_packets)
        
        # Calculate packet loss
        call_info['packet_loss_percent'] = self.calculate_packet_loss(rtp_packets)
        
        # Determine codec from payload type
        payload_types = set(p['payload_type'] for p in rtp_packets)
        if payload_types:
            most_common_pt = max(payload_types, key=lambda pt: sum(1 for p in rtp_packets if p['payload_type'] == pt))
            if most_common_pt in self.rtp_payload_types:
                call_info['codec_type'] = f"{most_common_pt}={self.rtp_payload_types[most_common_pt]}"
            else:
                call_info['codec_type'] = f"{most_common_pt}=Unknown"
        
        # Calculate peak bandwidth
        call_info['peak_bandwidth'] = self.calculate_peak_bandwidth(rtp_packets)
        
        # Calculate talk/silence ratio
        call_info['talk_silence_ratio'] = self.calculate_talk_silence_ratio(rtp_packets)
        
        # Calculate port range
        ports = set()
        for p in rtp_packets:
            ports.add(p['src_port'])
            ports.add(p['dst_port'])
        call_info['port_range_used'] = max(ports) - min(ports) if len(ports) > 1 else 0
        
        # Simple retransmission detection
        seq_counts = Counter(p['sequence_number'] for p in rtp_packets)
        call_info['retransmission_count'] = sum(count - 1 for count in seq_counts.values() if count > 1)
        
        # Estimate concurrent calls (simplified)
        call_info['concurrent_calls'] = 1  # Would need global analysis for accurate count

    def calculate_talk_silence_ratio(self, rtp_packets: List[Dict]) -> float:
        """Calculate talk/silence ratio as percentage of talk time (improved detection)"""
        if not rtp_packets:
            return 0.0
        
        # Analyze packet size variations and timing to detect silence
        talk_packets = 0
        total_packets = len(rtp_packets)
        
        if total_packets < 10:
            return 50.0  # Default for very short streams
        
        # Calculate average payload size
        payload_sizes = [p['payload_size'] for p in rtp_packets if p['payload_size'] > 0]
        if not payload_sizes:
            return 0.0
            
        avg_payload = statistics.mean(payload_sizes)
        
        # Detect talk vs silence based on multiple factors
        for i, packet in enumerate(rtp_packets):
            is_talk = False
            
            # Factor 1: Payload size significantly different from average (indicates activity)
            if packet['payload_size'] > avg_payload * 0.7:
                is_talk = True
                
            # Factor 2: Marker bit indicates start of talk spurt
            if packet.get('marker', 0):
                is_talk = True
                
            # Factor 3: Payload size variations (silence usually has consistent small payloads)
            if i > 0 and i < len(rtp_packets) - 1:
                prev_size = rtp_packets[i-1]['payload_size']
                next_size = rtp_packets[i+1]['payload_size']
                current_size = packet['payload_size']
                
                # If payload size varies significantly from neighbors, likely talk
                if abs(current_size - prev_size) > 10 or abs(current_size - next_size) > 10:
                    is_talk = True
            
            if is_talk:
                talk_packets += 1
                
        ratio = (talk_packets / total_packets * 100) if total_packets > 0 else 0.0
        return round(ratio, 1)

    def export_to_csv(self, calls: List[Dict], output_file: str):
        """Export call analysis results to CSV"""
        if not calls:
            print("No calls to export")
            return
            
        fieldnames = [
            'call_id', 'call_duration', 'caller_ip', 'callee_ip', 
            'start_time', 'end_time', 'avg_jitter', 'packet_loss_percent',
            'codec_type', 'setup_time', 'packets_per_second', 'bytes_per_second',
            'retransmission_count', 'response_code_variety', 'concurrent_calls',
            'jitter_variance', 'port_range_used', 'call_termination_method',
            'peak_bandwidth', 'talk_silence_ratio'
        ]
        
        try:
            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for call in calls:
                    # Format the row
                    row = {}
                    for field in fieldnames:
                        value = call.get(field, '')
                        if isinstance(value, float):
                            value = round(value, 3)
                        row[field] = value
                    writer.writerow(row)
                    
            print(f"Results exported to {output_file}")
            print(f"Analyzed {len(calls)} calls")
            
        except Exception as e:
            print(f"Error writing CSV file: {e}")

def main():
    parser = argparse.ArgumentParser(description="VoIP Call Tracer - Analyze PCAP files for VoIP call metadata")
    parser.add_argument("pcap_file", help="Input PCAP file path")
    parser.add_argument("-o", "--output", default="voip_analysis.csv", help="Output CSV file path")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    tracer = VoIPCallTracer()
    
    start_time = time.time()
    calls = tracer.analyze_pcap(args.pcap_file)
    end_time = time.time()
    
    if args.verbose:
        print(f"\nAnalysis completed in {end_time - start_time:.2f} seconds")
        for i, call in enumerate(calls, 1):
            print(f"\nCall {i}:")
            for key, value in call.items():
                print(f"  {key}: {value}")
    
    tracer.export_to_csv(calls, args.output)

if __name__ == "__main__":
    main()
