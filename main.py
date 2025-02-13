# file: main.py

import flet as ft
import whois
import dns.resolver
import re
from datetime import datetime
from typing import Optional, Dict, Any, List, Union

# Utility Functions
def validate_domain(domain: str) -> bool:
    domain_regex = r"^(?!\-)([a-zA-Z0-9\-]{1,63}(?<!\-)\.)+[a-zA-Z]{2,}$"
    return bool(re.match(domain_regex, domain))

def format_date(date: Union[datetime, List[datetime]]) -> Union[Optional[str], List[str]]:
    if isinstance(date, (list, tuple)):
        return [d.strftime("%b %d, %Y") for d in date if isinstance(d, datetime)]
    if isinstance(date, datetime):
        return date.strftime("%b %d, %Y")
    return None

def clean_status(status: Union[str, List[str]]) -> Union[Optional[str], List[str]]:
    if isinstance(status, (list, tuple)):
        return [s.split()[0] for s in status if isinstance(s, str)]
    if isinstance(status, str):
        return status.split()[0]
    return None

def handle_error(message: str) -> Dict[str, str]:
    return {"error": message}

def fetch_whois_info(domain: str) -> Union[Dict[str, Any], Dict[str, str]]:
    try:
        w = whois.whois(domain)
        return {
            "Registrar": w.registrar,
            "Created Date": format_date(w.creation_date),
            "Expiry Date": format_date(w.expiration_date),
            "Status": clean_status(w.status),
            "Nameservers": list(w.name_servers) if w.name_servers else None,
        }
    except whois.WhoisException as e:
        return handle_error(f"WHOIS lookup failed: {str(e)}")
    except Exception as e:
        return handle_error(f"Unexpected error fetching WHOIS: {str(e)}")

def fetch_dns_record(record_type: str, domain: str) -> Union[List[str], Dict[str, str]]:
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ['8.8.8.8', '1.1.1.1']
    try:
        answers = resolver.resolve(domain, record_type)
        return [rdata.to_text() for rdata in answers]
    except dns.resolver.NoAnswer:
        return handle_error(f"No {record_type} records found.")
    except dns.resolver.NXDOMAIN:
        return handle_error(f"Domain '{domain}' does not exist.")
    except dns.resolver.Timeout:
        return handle_error("DNS query timed out. Check your network.")
    except Exception as e:
        return handle_error(f"Error retrieving {record_type} records: {str(e)}")

def fetch_dns_records(domain: str) -> Dict[str, Union[List[str], str]]:
    record_types = ['A', 'NS', 'CNAME', 'MX', 'TXT']
    records = {}
    for record_type in record_types:
        result = fetch_dns_record(record_type, domain)
        records[record_type] = result if not isinstance(result, dict) else result['error']
    return records

# UI Function
def build_ui(page: ft.Page):
    status_bar = ft.Text("Ready", size=12, color=ft.colors.GRAY)
    domain_input = ft.TextField(label="Enter Domain", width=300)
    fetch_button = ft.IconButton(icon=ft.icons.SEARCH, tooltip="Fetch Data")
    refresh_button = ft.IconButton(icon=ft.icons.REFRESH, tooltip="Refresh Data")
    theme_toggle = ft.IconButton(icon=ft.icons.BRIGHTNESS_6, tooltip="Toggle Dark/Light Mode")
    whois_content, dns_content = ft.Column(), ft.Column()
    loading_indicator = ft.ProgressRing(visible=False)

    def update_status(message):
        status_bar.value = message
        page.update()

    async def fetch_data(e):
        domain = domain_input.value.strip()
        if not domain:
            update_status("Error: Invalid Domain")
            return

        loading_indicator.visible = True
        update_status("Fetching Data...")
        page.update()

        try:
            whois_info = await fetch_whois_info(domain)
            dns_info = await fetch_dns_records(domain)
            whois_content.controls.clear()
            dns_content.controls.clear()

            if whois_info:
                for key, value in whois_info.items():
                    whois_content.controls.append(
                        ft.Card(
                            content=ft.Row([ft.Text(key), ft.Text(value)], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                            elevation=2,
                        )
                    )
            for record_type, records in dns_info.items():
                dns_content.controls.append(
                    ft.Collapsible(
                        label=record_type,
                        content=ft.Column([ft.Text(record) for record in records]),
                    )
                )
            update_status("Ready")
        except Exception as e:
            update_status(f"Error: {str(e)}")
        loading_indicator.visible = False
        page.update()

    fetch_button.on_click = fetch_data
    refresh_button.on_click = fetch_data

    def toggle_theme(e):
        page.theme = ft.ThemeMode.DARK if page.theme == ft.ThemeMode.LIGHT else ft.ThemeMode.LIGHT
        theme_toggle.icon = ft.icons.BRIGHTNESS_7 if page.theme == ft.ThemeMode.DARK else ft.icons.BRIGHTNESS_6
        page.update()

    theme_toggle.on_click = toggle_theme

    tabs = ft.Tabs(
        selected_index=0,
        tabs=[
            ft.Tab(text="WHOIS", content=whois_content),
            ft.Tab(text="DNS", content=dns_content),
        ],
    )

    page.add(
        ft.Row([domain_input, fetch_button, refresh_button, theme_toggle]),
        loading_indicator,
        tabs,
        status_bar,
    )
    page.on_key_down = lambda e: (
        tabs.selected_index := (tabs.selected_index + 1) % len(tabs.tabs) if e.key == ft.KeyCode.TAB else None
    )

if __name__ == "__main__":
    ft.app(target=build_ui)
