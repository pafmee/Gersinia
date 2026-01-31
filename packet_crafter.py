#!/usr/bin/env python3
"""
Packet Crafting Module for Network Attack Tool
Allows users to create and send custom network packets
"""

import customtkinter as ctk
from scapy.all import *
import threading
import json

class PacketCrafter:
    def __init__(self, parent, log_callback, selected_interface_callback):
        self.parent = parent
        self.log_callback = log_callback
        self.selected_interface_callback = selected_interface_callback
        
        # Packet layers
        self.layers = {}
        self.packet = None
        
        # Create packet crafting window
        self.create_window()
    
    def create_window(self):
        """Create packet crafting interface"""
        self.window = ctk.CTkToplevel(self.parent)
        self.window.title("Packet Crafter")
        self.window.geometry("800x600")
        
        # Main container
        main_container = ctk.CTkFrame(self.window)
        main_container.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Left panel - Layer configuration
        left_panel = ctk.CTkFrame(main_container, width=400)
        left_panel.pack(side="left", fill="y", padx=(0, 10))
        left_panel.pack_propagate(False)
        
        ctk.CTkLabel(left_panel, text="Packet Layers", font=("Arial", 14, "bold")).pack(padx=10, pady=10)
        
        # Layer selection
        layer_frame = ctk.CTkFrame(left_panel)
        layer_frame.pack(fill="x", padx=10, pady=5)
        
        ctk.CTkLabel(layer_frame, text="Add Layer:").pack(side="left", padx=5)
        self.layer_combo = ctk.CTkComboBox(
            layer_frame, 
            values=["Ethernet", "IP", "TCP", "UDP", "ARP", "ICMP", "DNS", "DHCP"],
            state="readonly"
        )
        self.layer_combo.pack(side="left", padx=5)
        self.layer_combo.set("Ethernet")
        
        ctk.CTkButton(layer_frame, text="Add", command=self.add_layer).pack(side="left", padx=5)
        
        # Layer configuration scrollable frame
        self.layer_config_frame = ctk.CTkScrollableFrame(left_panel, height=400)
        self.layer_config_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Right panel - Packet preview and actions
        right_panel = ctk.CTkFrame(main_container)
        right_panel.pack(side="right", fill="both", expand=True)
        
        ctk.CTkLabel(right_panel, text="Packet Preview", font=("Arial", 14, "bold")).pack(padx=10, pady=10)
        
        # Packet preview text
        self.preview_text = ctk.CTkTextbox(right_panel, height=300)
        self.preview_text.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Action buttons
        button_frame = ctk.CTkFrame(right_panel)
        button_frame.pack(fill="x", padx=10, pady=10)
        
        ctk.CTkButton(button_frame, text="Build Packet", command=self.build_packet).pack(side="left", padx=5)
        ctk.CTkButton(button_frame, text="Send Packet", command=self.send_packet).pack(side="left", padx=5)
        ctk.CTkButton(button_frame, text="Save Template", command=self.save_template).pack(side="left", padx=5)
        ctk.CTkButton(button_frame, text="Load Template", command=self.load_template).pack(side="left", padx=5)
        
        # Send options
        send_frame = ctk.CTkFrame(right_panel)
        send_frame.pack(fill="x", padx=10, pady=5)
        
        self.send_count_entry = ctk.CTkEntry(send_frame, width=100)
        self.send_count_entry.insert(0, "1")
        self.send_count_entry.pack(side="left", padx=5)
        
        ctk.CTkLabel(send_frame, text="count(s)").pack(side="left", padx=5)
        
        self.interval_entry = ctk.CTkEntry(send_frame, width=100)
        self.interval_entry.insert(0, "1.0")
        self.interval_entry.pack(side="left", padx=5)
        
        ctk.CTkLabel(send_frame, text="second(s) interval").pack(side="left", padx=5)
    
    def add_layer(self):
        """Add a new layer to the packet"""
        layer_type = self.layer_combo.get()
        layer_name = f"{layer_type}_{len(self.layers)}"
        
        # Create layer frame
        layer_frame = ctk.CTkFrame(self.layer_config_frame)
        layer_frame.pack(fill="x", padx=5, pady=5)
        
        ctk.CTkLabel(layer_frame, text=layer_type, font=("Arial", 10, "bold")).pack(anchor="w", padx=5, pady=2)
        
        # Layer configuration fields
        fields = {}
        
        if layer_type == "Ethernet":
            fields["dst"] = ctk.CTkEntry(layer_frame, placeholder_text="00:00:00:00:00:00")
            fields["src"] = ctk.CTkEntry(layer_frame, placeholder_text="00:00:00:00:00:00")
            fields["type"] = ctk.CTkEntry(layer_frame, placeholder_text="0x0800")
            
            fields["dst"].pack(fill="x", padx=5, pady=2)
            fields["src"].pack(fill="x", padx=5, pady=2)
            fields["type"].pack(fill="x", padx=5, pady=2)
            
        elif layer_type == "IP":
            fields["src"] = ctk.CTkEntry(layer_frame, placeholder_text="192.168.1.1")
            fields["dst"] = ctk.CTkEntry(layer_frame, placeholder_text="192.168.1.2")
            fields["ttl"] = ctk.CTkEntry(layer_frame, placeholder_text="64")
            fields["proto"] = ctk.CTkEntry(layer_frame, placeholder_text="6")
            
            fields["src"].pack(fill="x", padx=5, pady=2)
            fields["dst"].pack(fill="x", padx=5, pady=2)
            fields["ttl"].pack(fill="x", padx=5, pady=2)
            fields["proto"].pack(fill="x", padx=5, pady=2)
            
        elif layer_type == "TCP":
            fields["sport"] = ctk.CTkEntry(layer_frame, placeholder_text="80")
            fields["dport"] = ctk.CTkEntry(layer_frame, placeholder_text="8080")
            fields["seq"] = ctk.CTkEntry(layer_frame, placeholder_text="1000")
            fields["ack"] = ctk.CTkEntry(layer_frame, placeholder_text="0")
            fields["flags"] = ctk.CTkEntry(layer_frame, placeholder_text="S")
            
            fields["sport"].pack(fill="x", padx=5, pady=2)
            fields["dport"].pack(fill="x", padx=5, pady=2)
            fields["seq"].pack(fill="x", padx=5, pady=2)
            fields["ack"].pack(fill="x", padx=5, pady=2)
            fields["flags"].pack(fill="x", padx=5, pady=2)
            
        elif layer_type == "UDP":
            fields["sport"] = ctk.CTkEntry(layer_frame, placeholder_text="53")
            fields["dport"] = ctk.CTkEntry(layer_frame, placeholder_text="5353")
            fields["len"] = ctk.CTkEntry(layer_frame, placeholder_text="8")
            
            fields["sport"].pack(fill="x", padx=5, pady=2)
            fields["dport"].pack(fill="x", padx=5, pady=2)
            fields["len"].pack(fill="x", padx=5, pady=2)
            
        elif layer_type == "ARP":
            fields["pdst"] = ctk.CTkEntry(layer_frame, placeholder_text="192.168.1.2")
            fields["psrc"] = ctk.CTkEntry(layer_frame, placeholder_text="192.168.1.1")
            fields["hwsrc"] = ctk.CTkEntry(layer_frame, placeholder_text="00:11:22:33:44:55")
            
            fields["pdst"].pack(fill="x", padx=5, pady=2)
            fields["psrc"].pack(fill="x", padx=5, pady=2)
            fields["hwsrc"].pack(fill="x", padx=5, pady=2)
            
        elif layer_type == "ICMP":
            fields["type"] = ctk.CTkEntry(layer_frame, placeholder_text="8")
            fields["code"] = ctk.CTkEntry(layer_frame, placeholder_text="0")
            fields["id"] = ctk.CTkEntry(layer_frame, placeholder_text="1")
            fields["seq"] = ctk.CTkEntry(layer_frame, placeholder_text="1")
            
            fields["type"].pack(fill="x", padx=5, pady=2)
            fields["code"].pack(fill="x", padx=5, pady=2)
            fields["id"].pack(fill="x", padx=5, pady=2)
            fields["seq"].pack(fill="x", padx=5, pady=2)
        
        # Remove button
        remove_button = ctk.CTkButton(layer_frame, text="Remove", command=lambda lf=layer_frame, ln=layer_name: self.remove_layer(lf, ln))
        remove_button.pack(fill="x", padx=5, pady=2)
        
        self.layers[layer_name] = {
            "type": layer_type,
            "frame": layer_frame,
            "fields": fields
        }
    
    def remove_layer(self, layer_frame, layer_name):
        """Remove a layer from the packet"""
        layer_frame.destroy()
        del self.layers[layer_name]
    
    def build_packet(self):
        """Build the packet from configured layers"""
        try:
            self.packet = None
            
            # Order layers correctly
            layer_order = ["Ethernet", "ARP", "IP", "ICMP", "UDP", "TCP", "DNS", "DHCP"]
            
            for layer_type in layer_order:
                for layer_name, layer_data in self.layers.items():
                    if layer_data["type"] == layer_type:
                        layer_packet = self.create_layer_packet(layer_data)
                        if layer_packet:
                            if self.packet is None:
                                self.packet = layer_packet
                            else:
                                self.packet /= layer_packet
            
            if self.packet:
                self.preview_text.delete("1.0", "end")
                self.preview_text.insert("1.0", self.packet.show())
                self.log_callback(f"Packet built successfully: {len(self.packet)} bytes")
            else:
                self.log_callback("Error: No layers configured")
                
        except Exception as e:
            self.log_callback(f"Error building packet: {str(e)}")
    
    def create_layer_packet(self, layer_data):
        """Create a Scapy layer from configuration"""
        layer_type = layer_data["type"]
        fields = layer_data["fields"]
        
        try:
            if layer_type == "Ethernet":
                dst = fields["dst"].get() or "ff:ff:ff:ff:ff:ff"
                src = fields["src"].get() or get_if_hwaddr(self.selected_interface_callback())
                type_val = int(fields["type"].get(), 0) if fields["type"].get() else 0x0800
                return Ether(dst=dst, src=src, type=type_val)
            
            elif layer_type == "IP":
                src = fields["src"].get() or "192.168.1.1"
                dst = fields["dst"].get() or "192.168.1.2"
                ttl = int(fields["ttl"].get()) if fields["ttl"].get() else 64
                proto = int(fields["proto"].get()) if fields["proto"].get() else 6
                return IP(src=src, dst=dst, ttl=ttl, proto=proto)
            
            elif layer_type == "TCP":
                sport = int(fields["sport"].get()) if fields["sport"].get() else 80
                dport = int(fields["dport"].get()) if fields["dport"].get() else 8080
                seq = int(fields["seq"].get()) if fields["seq"].get() else 1000
                ack = int(fields["ack"].get()) if fields["ack"].get() else 0
                flags = fields["flags"].get() or "S"
                return TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags)
            
            elif layer_type == "UDP":
                sport = int(fields["sport"].get()) if fields["sport"].get() else 53
                dport = int(fields["dport"].get()) if fields["dport"].get() else 5353
                return UDP(sport=sport, dport=dport)
            
            elif layer_type == "ARP":
                pdst = fields["pdst"].get() or "192.168.1.2"
                psrc = fields["psrc"].get() or "192.168.1.1"
                hwsrc = fields["hwsrc"].get() or get_if_hwaddr(self.selected_interface_callback())
                return ARP(pdst=pdst, psrc=psrc, hwsrc=hwsrc)
            
            elif layer_type == "ICMP":
                type_val = int(fields["type"].get()) if fields["type"].get() else 8
                code = int(fields["code"].get()) if fields["code"].get() else 0
                id_val = int(fields["id"].get()) if fields["id"].get() else 1
                seq = int(fields["seq"].get()) if fields["seq"].get() else 1
                return ICMP(type=type_val, code=code, id=id_val, seq=seq)
                
        except Exception as e:
            self.log_callback(f"Error creating {layer_type} layer: {str(e)}")
            return None
    
    def send_packet(self):
        """Send the built packet"""
        if not self.packet:
            self.log_callback("Error: No packet built")
            return
        
        try:
            count = int(self.send_count_entry.get())
            interval = float(self.interval_entry.get())
            interface = self.selected_interface_callback()
            
            if not interface:
                self.log_callback("Error: No network interface selected")
                return
            
            def send_packets():
                for i in range(count):
                    sendp(self.packet, iface=interface, verbose=False)
                    self.log_callback(f"Sent packet {i+1}/{count}")
                    if i < count - 1 and interval > 0:
                        time.sleep(interval)
            
            threading.Thread(target=send_packets, daemon=True).start()
            
        except Exception as e:
            self.log_callback(f"Error sending packet: {str(e)}")
    
    def save_template(self):
        """Save packet configuration as template"""
        try:
            template = {}
            for layer_name, layer_data in self.layers.items():
                template[layer_name] = {
                    "type": layer_data["type"],
                    "fields": {}
                }
                for field_name, field_widget in layer_data["fields"].items():
                    template[layer_name]["fields"][field_name] = field_widget.get()
            
            filename = f"packet_template_{int(time.time())}.json"
            with open(filename, "w") as f:
                json.dump(template, f, indent=2)
            
            self.log_callback(f"Template saved: {filename}")
            
        except Exception as e:
            self.log_callback(f"Error saving template: {str(e)}")
    
    def load_template(self):
        """Load packet configuration from template"""
        try:
            from tkinter import filedialog
            filename = filedialog.askopenfilename(
                title="Load Packet Template",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
            )
            
            if filename:
                with open(filename, "r") as f:
                    template = json.load(f)
                
                # Clear existing layers
                for layer_name in list(self.layers.keys()):
                    self.layers[layer_name]["frame"].destroy()
                self.layers.clear()
                
                # Load template layers
                for layer_name, layer_config in template.items():
                    self.layer_combo.set(layer_config["type"])
                    self.add_layer()
                    
                    # Update the last added layer with template values
                    last_layer = list(self.layers.keys())[-1]
                    for field_name, field_value in layer_config["fields"].items():
                        if field_name in self.layers[last_layer]["fields"]:
                            self.layers[last_layer]["fields"][field_name].delete(0, "end")
                            self.layers[last_layer]["fields"][field_name].insert(0, field_value or "")
                
                self.log_callback(f"Template loaded: {filename}")
                
        except Exception as e:
            self.log_callback(f"Error loading template: {str(e)}")
    
    def show(self):
        """Show the packet crafting window"""
        self.window.deiconify()
        self.window.lift()