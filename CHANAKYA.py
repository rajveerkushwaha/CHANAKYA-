import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import requests
import threading
import time
import csv
import json
import subprocess

# VirusTotal API information
API_KEY = '94346a8a2cdcb0c44e152d6633152a64098360a52766e71636e271fd9b75f040'
FILE_SCAN_URL = 'https://www.virustotal.com/vtapi/v2/file/scan'
URL_SCAN_URL = 'https://www.virustotal.com/vtapi/v2/url/scan'
URL_REPORT_URL = 'https://www.virustotal.com/vtapi/v2/url/report'

scanning_in_progress = False
stop_loading = threading.Event()

def update_loading_status(message):
    loading_label.config(text=message)
    root.update_idletasks()

def loading_spinner():
    spinner_symbols = "|/-\\"
    while scanning_in_progress:
        for symbol in spinner_symbols:
            if stop_loading.is_set():
                break
            update_loading_status(f"Scanning in progress... {symbol}")
            time.sleep(0.2)
        if stop_loading.is_set():
            break
    update_loading_status("")

def display_result(title, result_text):
    result_text = result_text.strip()
    output_box.config(state=tk.NORMAL)
    output_box.insert(tk.END, f"=== {title} ===\n", "title")
    output_box.insert(tk.END, f"{result_text}\n\n", "content")
    output_box.config(state=tk.DISABLED)

def get_url_report(scan_id):
    params = {'apikey': API_KEY, 'resource': scan_id}
    response = requests.get(URL_REPORT_URL, params=params)
    result = response.json()
    return result

def scan_file():
    global scanning_in_progress
    file_path = filedialog.askopenfilename(title="Select a file to scan", filetypes=[("All files", "*.*")])
    if file_path:
        def run_scan():
            global stop_loading
            try:
                scanning_in_progress = True
                stop_loading.clear()
                update_loading_status("Starting file scan...")
                with open(file_path, 'rb') as file:
                    files = {'file': (file_path, file)}
                    params = {'apikey': API_KEY}
                    response = requests.post(FILE_SCAN_URL, files=files, params=params)
                    result = response.json()
                    scan_id = result.get('scan_id', 'N/A')
                    response_code = result.get('response_code', 'N/A')
                    display_result("File Scan Result", f"Scan ID: {scan_id}\nResponse Code: {response_code}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to scan file: {str(e)}")
            finally:
                scanning_in_progress = False
                stop_loading.set()

        threading.Thread(target=run_scan).start()
        threading.Thread(target=loading_spinner).start()

def scan_url():
    global scanning_in_progress
    url = url_entry.get()
    if url:
        def run_scan():
            global stop_loading
            try:
                scanning_in_progress = True
                stop_loading.clear()
                update_loading_status("Starting URL scan...")
                params = {'apikey': API_KEY, 'url': url}
                response = requests.post(URL_SCAN_URL, data=params)
                result = response.json()
                scan_id = result.get('scan_id', 'N/A')
                response_code = result.get('response_code', 'N/A')
                if response_code == 1:
                    update_loading_status("Fetching report...")
                    time.sleep(10)
                    report = get_url_report(scan_id)
                    positives = report.get('positives', 0)
                    total = report.get('total', 0)
                    verdict = f"Malicious: {positives}/{total} engines detected this URL as malicious."
                    if positives > 0:
                        verdict = f"⚠️ WARNING: {positives} out of {total} engines flagged this URL as unsafe!"
                    else:
                        verdict = f"✅ SAFE: No engines flagged this URL as malicious."
                    display_result("URL Scan Result", f"Scan ID: {scan_id}\nResponse Code: {response_code}\n{verdict}")
                else:
                    display_result("URL Scan Result", f"Scan ID: {scan_id}\nResponse Code: {response_code}\nNo further details available.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to scan URL: {str(e)}")
            finally:
                scanning_in_progress = False
                stop_loading.set()

        threading.Thread(target=run_scan).start()
        threading.Thread(target=loading_spinner).start()

def scan_network():
    global scanning_in_progress
    ip_address = ip_entry.get()
    if ip_address:
        def run_scan():
            global stop_loading
            try:
                scanning_in_progress = True
                stop_loading.clear()
                update_loading_status("Starting Nmap scan...")
                result = subprocess.run(['nmap', '-A', ip_address], capture_output=True, text=True)
                if result.returncode == 0:
                    display_result("Nmap Scan Result", result.stdout)
                else:
                    display_result("Nmap Scan Result", "Error running Nmap scan.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to scan network: {str(e)}")
            finally:
                scanning_in_progress = False
                stop_loading.set()

        threading.Thread(target=run_scan).start()
        threading.Thread(target=loading_spinner).start()

def toggle_buttons(state):
    file_button.config(state=state)
    url_button.config(state=state)
    network_button.config(state=state)
    clear_button.config(state=state)
    export_text_button.config(state=state)
    export_csv_button.config(state=state)
    export_json_button.config(state=state)

def export_to_text():
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
    if file_path:
        with open(file_path, 'w') as file:
            file.write(output_box.get(1.0, tk.END))

def export_to_csv():
    file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
    if file_path:
        lines = output_box.get(1.0, tk.END).strip().split('\n\n')
        with open(file_path, 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["Title", "Content"])
            for line in lines:
                parts = line.split('\n', 1)
                if len(parts) == 2:
                    writer.writerow(parts)

def export_to_json():
    file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
    if file_path:
        result_text = output_box.get(1.0, tk.END).strip()
        results = [{"title": line.split('\n')[0], "content": line.split('\n', 1)[1]} for line in result_text.split('\n\n') if line]
        with open(file_path, 'w') as file:
            json.dump(results, file, indent=4)

def show_page(page_name):
    for widget in page_frame.winfo_children():
        widget.pack_forget()
    
    # Common elements
    if page_name in ["File Scan", "URL Scan", "Network Scan", "Results"]:
        output_frame.pack(fill=tk.BOTH, expand=True)
    else:
        welcome_frame.pack(fill=tk.BOTH, expand=True)
    
    if page_name == "Welcome":
        welcome_frame.pack(fill=tk.BOTH, expand=True)
    elif page_name == "File Scan":
        file_scan_frame.pack(fill=tk.BOTH, expand=True)
    elif page_name == "URL Scan":
        url_scan_frame.pack(fill=tk.BOTH, expand=True)
    elif page_name == "Network Scan":
        network_scan_frame.pack(fill=tk.BOTH, expand=True)
    elif page_name == "Results":
        output_frame.pack(fill=tk.BOTH, expand=True)

# Tkinter GUI setup
root = tk.Tk()
root.title("Chanakya")
root.geometry("800x700")

# Professional theme colors
bg_color = "#FFFFFF"  # White background for a clean look
fg_color = "#000000"  # Black text for high contrast
button_color = "#0044CC"  # Dark blue buttons for a professional appearance
highlight_color = "#0055FF"  # Blue highlight for emphasis
entry_bg_color = "#F5F5F5"  # Light grey background for entry fields

root.configure(bg=bg_color)

# Create and place frames for better layout management
main_frame = tk.Frame(root, bg=bg_color)
main_frame.pack(fill=tk.BOTH, expand=True)

page_frame = tk.Frame(root, bg=bg_color)
page_frame.pack(fill=tk.BOTH, expand=True)

# Welcome Frame
welcome_frame = tk.Frame(page_frame, bg=bg_color)
welcome_label = tk.Label(welcome_frame, text="WELCOME TO CHANAKYA", font=("Arial", 24), fg=highlight_color, bg=bg_color)
welcome_label.pack(pady=20)
description_label = tk.Label(welcome_frame, text="What would you like to do?", font=("Arial", 18), fg=fg_color, bg=bg_color)
description_label.pack(pady=10)
file_button = tk.Button(welcome_frame, text="File Scan", command=lambda: show_page("File Scan"), bg=button_color, fg=bg_color)
file_button.pack(pady=10, fill=tk.X)
url_button = tk.Button(welcome_frame, text="URL Scan", command=lambda: show_page("URL Scan"), bg=button_color, fg=bg_color)
url_button.pack(pady=10, fill=tk.X)
network_button = tk.Button(welcome_frame, text="Network Scan", command=lambda: show_page("Network Scan"), bg=button_color, fg=bg_color)
network_button.pack(pady=10, fill=tk.X)
clear_button = tk.Button(welcome_frame, text="Clear Results", command=lambda: output_box.delete(1.0, tk.END), bg=button_color, fg=bg_color)
clear_button.pack(pady=10, fill=tk.X)

# File Scan Frame
file_scan_frame = tk.Frame(page_frame, bg=bg_color)
file_scan_label = tk.Label(file_scan_frame, text="Select a file to scan", font=("Arial", 18), fg=fg_color, bg=bg_color)
file_scan_label.pack(pady=20)
scan_file_button = tk.Button(file_scan_frame, text="Scan File", command=scan_file, bg=button_color, fg=bg_color)
scan_file_button.pack(pady=10)
back_button_file = tk.Button(file_scan_frame, text="Back to Main", command=lambda: show_page("Welcome"), bg=button_color, fg=bg_color)
back_button_file.pack(pady=10)

# URL Scan Frame
url_scan_frame = tk.Frame(page_frame, bg=bg_color)
url_scan_label = tk.Label(url_scan_frame, text="Enter URL to scan", font=("Arial", 18), fg=fg_color, bg=bg_color)
url_scan_label.pack(pady=20)
url_entry = tk.Entry(url_scan_frame, bg=entry_bg_color, fg=fg_color)
url_entry.pack(pady=10, fill=tk.X, padx=10)
scan_url_button = tk.Button(url_scan_frame, text="Scan URL", command=scan_url, bg=button_color, fg=bg_color)
scan_url_button.pack(pady=10)
back_button_url = tk.Button(url_scan_frame, text="Back to Main", command=lambda: show_page("Welcome"), bg=button_color, fg=bg_color)
back_button_url.pack(pady=10)

# Network Scan Frame
network_scan_frame = tk.Frame(page_frame, bg=bg_color)
network_scan_label = tk.Label(network_scan_frame, text="Enter IP address to scan", font=("Arial", 18), fg=fg_color, bg=bg_color)
network_scan_label.pack(pady=20)
ip_entry = tk.Entry(network_scan_frame, bg=entry_bg_color, fg=fg_color)
ip_entry.pack(pady=10, fill=tk.X, padx=10)
scan_network_button = tk.Button(network_scan_frame, text="Scan Network", command=scan_network, bg=button_color, fg=bg_color)
scan_network_button.pack(pady=10)
back_button_network = tk.Button(network_scan_frame, text="Back to Main", command=lambda: show_page("Welcome"), bg=button_color, fg=bg_color)
back_button_network.pack(pady=10)

# Results Frame
output_frame = tk.Frame(page_frame, bg=bg_color)
output_box = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, height=15, bg=entry_bg_color, fg=fg_color, font=("Arial", 12))
output_box.pack(pady=20, fill=tk.BOTH, expand=True)

export_text_button = tk.Button(output_frame, text="Export as Text", command=export_to_text, bg=button_color, fg=bg_color)
export_text_button.pack(pady=5, side=tk.LEFT, padx=10)
export_csv_button = tk.Button(output_frame, text="Export as CSV", command=export_to_csv, bg=button_color, fg=bg_color)
export_csv_button.pack(pady=5, side=tk.LEFT, padx=10)
export_json_button = tk.Button(output_frame, text="Export as JSON", command=export_to_json, bg=button_color, fg=bg_color)
export_json_button.pack(pady=5, side=tk.LEFT, padx=10)
back_button_results = tk.Button(output_frame, text="Back to Main", command=lambda: show_page("Welcome"), bg=button_color, fg=bg_color)
back_button_results.pack(pady=5, side=tk.LEFT, padx=10)

# Loading status label
loading_label = tk.Label(root, text="", font=("Arial", 14), fg=fg_color, bg=bg_color)
loading_label.pack(pady=10)

# Start with the Welcome Page
show_page("Welcome")

# Run the Tkinter main loop
root.mainloop()
