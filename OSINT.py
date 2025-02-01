import tkinter as tk
from tkinter import ttk, messagebox
import requests
import whois
from bs4 import BeautifulSoup

def search_user():
    username = entry.get()
    if not username:
        messagebox.showerror("Error", "Enter a username.")
        return

    result_text.set("Searching...")

    sites = {
        "GitHub": f"https://github.com/{username}",
        "Instagram": f"https://www.instagram.com/{username}",
        "Twitter": f"https://twitter.com/{username}",
        "Reddit": f"https://www.reddit.com/user/{username}",
        "Facebook": f"https://www.facebook.com/{username}",
        "LinkedIn": f"https://www.linkedin.com/in/{username}",
        "TikTok": f"https://www.tiktok.com/@{username}",
        "Snapchat": f"https://www.snapchat.com/add/{username}"
    }

    found = []

    for site, url in sites.items():
        try:
            response = requests.get(url)
            if response.status_code == 200:
                found.append(f"{site}: {url}")
        except:
            pass

    result_text.set("\n".join(found) if found else "User not found.")

def search_ip():
    ip = entry_ip.get()
    if not ip:
        messagebox.showerror("Error", "Enter an IP address.")
        return

    try:
        url = f"http://ip-api.com/json/{ip}"
        response = requests.get(url).json()
        result_ip.set(f"Country: {response['country']}\nCity: {response['city']}\nISP: {response['isp']}")
    except:
        result_ip.set("Error retrieving IP data.")

def search_domain():
    domain = entry_domain.get()
    if not domain:
        messagebox.showerror("Error", "Enter a domain.")
        return

    try:
        domain_info = whois.whois(domain)
        result_domain.set(f"Registrar: {domain_info.registrar}\nCreation Date: {domain_info.creation_date}")
    except:
        result_domain.set("Error retrieving WHOIS data.")

root = tk.Tk()
root.title("OSINT Tool")
root.geometry("500x600")

tk.Label(root, text="Enter Username:", font=("Arial", 12)).pack(pady=5)
entry = tk.Entry(root, font=("Arial", 12))
entry.pack(pady=5)
tk.Button(root, text="Search User", command=search_user).pack(pady=5)
result_text = tk.StringVar()
tk.Label(root, textvariable=result_text, fg="blue").pack(pady=5)

tk.Label(root, text="Enter IP:", font=("Arial", 12)).pack(pady=5)
entry_ip = tk.Entry(root, font=("Arial", 12))
entry_ip.pack(pady=5)
tk.Button(root, text="Search IP", command=search_ip).pack(pady=5)
result_ip = tk.StringVar()
tk.Label(root, textvariable=result_ip, fg="blue").pack(pady=5)

tk.Label(root, text="Enter Domain:", font=("Arial", 12)).pack(pady=5)
entry_domain = tk.Entry(root, font=("Arial", 12))
entry_domain.pack(pady=5)
tk.Button(root, text="Search Domain", command=search_domain).pack(pady=5)
result_domain = tk.StringVar()
tk.Label(root, textvariable=result_domain, fg="blue").pack(pady=5)

root.mainloop()