import requests                  # Import biblioteki requests do wykonywania zapytań HTTP/HTTPS do API zewnętrznych
import sys                       # Import modułu sys do obsługi argumentów wiersza poleceń i zarządzania procesem
import json                      # Import modułu json do parsowania i generowania danych w formacie JSON
import time                      # Import modułu time do funkcji opóźnień (np. sleep dla rate limitingu)
from datetime import datetime    # Import klasy datetime z modułu datetime do generowania znaczników czasu
from vt import Client            # Import oficjalnego klienta VirusTotal z biblioteki vt-py

# Prosta funkcja walidująca adres IP (IPv4)
def is_valid_ip(ip):
    """
    Sprawdza czy podany string wygląda na poprawny adres IPv4.
    Prosta walidacja bez użycia dodatkowych bibliotek.
    """
    parts = ip.split('.')
    if len(parts) != 4:          # IPv4 musi mieć 4 oktety oddzielone kropkami
        return False
    for part in parts:
        if not part.isdigit():   # Każda część musi być liczbą
            return False
        num = int(part)
        if num < 0 or num > 255: # Zakres wartości oktetu: 0-255
            return False
    return True

# Definicja klasy Colors przechowującej kody ANSI do kolorowania wyjścia w terminalu
class Colors:
    BrightRed = "\033[1;91m"     # Kod ANSI dla jasnoczerwonego tekstu (błędy, ostrzeżenia)
    BrightGreen = "\033[1;92m"   # Kod ANSI dla jasnozielonego tekstu (sukces, potwierdzenia)
    BrightYellow = "\033[1;93m"  # Kod ANSI dla jasnożółtego tekstu (informacje, postępy)
    BrightWhite = "\033[1;97m"   # Kod ANSI dla jasnobiałego tekstu (główne komunikaty)
    Cyan = "\033[1;96m"          # Kod ANSI dla cyjanowego tekstu (statusy, nagłówki)
    Reset = "\033[0m"            # Kod ANSI do resetowania kolorów tekstu do domyślnych
    Blue = "\033[1;94m"          # Kod ANSI dla niebieskiego tekstu
    Gray = "\033[0;37m"          # Kod ANSI dla szarego tekstu (mniej ważne informacje)
    Orange = "\033[38;5;208m"    # Kod ANSI dla pomarańczowego tekstu (256-color palette)
    Mint = "\033[38;5;121m"      # Kod ANSI dla miętowego tekstu (256-color palette)
    Purple = "\033[35m"          # Kod ANSI dla fioletowego tekstu
    DarkGreen = "\033[0;32m"     # Kod ANSI dla ciemnozielonego tekstu
    LightGreen = "\033[92m"      # Kod ANSI dla jasnozielonego tekstu (alternatywny)

# Definicja zmiennej ASCII_BANNER zawierającej artystyczny banner startowy programu z użyciem f-string i kolorów
ASCII_BANNER = rf"""{Colors.LightGreen}  
  ____ _               _    ___ ____    
 / ___| |__   ___  ___| | _|_ _|  _ \   
| |   | '_ \ / _ \/ __| |/ /| || |_) |  
| |___| | | |  __/ (__|   < | ||  __/   
 \____|_| |_|\___|\___|_|\_\___|_|      
                                         
> CHECK_IP - Bulk Reputation Scanner  
> (c) 2026 by Łukasz Wójcik  version 1.3 
> GitHub: https://github.com/lukaszwojcikdev/check-ip-reputation     
> Usage: check_ip.py <LIST_IP_FILE.txt>  
{Colors.Reset}"""                                                                                   # Zakończenie multi-line stringa z resetem kolorów na koniec

# Definicja funkcji load_config do wczytywania konfiguracji z pliku JSON
def load_config(config_file="config.json"):                                                         # Deklaracja funkcji z domyślną nazwą pliku config.json
    try:                                                                                            # Rozpoczęcie bloku try do obsługi wyjątków
        with open(config_file, "r") as f:                                                           # Otwórz plik config_file w trybie do odczytu jako f
            return json.load(f)                                                                     # Załaduj zawartość pliku JSON i zwróć jako słownik Python
    except FileNotFoundError:                                                                       # Obsługa wyjątku gdy plik konfiguracyjny nie istnieje
        print(f"{Colors.BrightRed}X BŁĄD: Plik {config_file} nie istnieje!{Colors.Reset}")          # Wyświetl błąd w czerwonym kolorze
        sys.exit(1)                                                                                 # Zakończ program z kodem błędu 1
    except json.JSONDecodeError:                                                                    # Obsługa wyjątku gdy plik JSON ma niepoprawny format
        print(f"{Colors.BrightRed}X BŁĄD: Niepoprawny format JSON w {config_file}!{Colors.Reset}")  # Wyświetl błąd formatu JSON w czerwonym kolorze
        sys.exit(1)                                                                                 # Zakończ program z kodem błędu 1

# Definicja klasy AbuseIPDBChecker do obsługi interfejsu API AbuseIPDB
class AbuseIPDBChecker:                                                                             # Deklaracja klasy
    def __init__(self, api_key):                                                                    # Konstruktor klasy przyjmujący klucz API jako argument
        self.api_key = api_key                                                                      # Przypisz klucz API do zmiennej instancji self.api_key

    @staticmethod                                                                                   # Dekorator wskazujący, że metoda jest statyczna (nie wymaga instancji klasy)
    def extract_abuse_ipdb_category(category_number):                                               # Deklaracja metody statycznej do mapowania kategorii
        
        # Definicja słownika mapping do konwersji numerów kategorii AbuseIPDB na czytelne opisy z emoji
        mapping = {                                                                                 # Rozpoczęcie definicji słownika mapping
            "1": "🌐 DNS Compromise",                                                               # Mapowanie kategorii 1 na opis DNS Compromise
            "2": "☢️ DNS Poisoning",                                                                 # Mapowanie kategorii 2 na opis DNS Poisoning
            "3": "🛒 Fraud Orders",                                                                 # Mapowanie kategorii 3 na opis Fraud Orders
            "4": "📧 DDOS Attack",                                                                  # Mapowanie kategorii 4 na opis DDOS Attack
            "5": "📁 FTP Brute-Force",                                                              # Mapowanie kategorii 5 na opis FTP Brute-Force
            "6": "💀 Ping of Death",                                                                # Mapowanie kategorii 6 na opis Ping of Death
            "7": "🎣 Phishing",                                                                     # Mapowanie kategorii 7 na opis Phishing
            "8": "📞 Fraud VOIP",                                                                   # Mapowanie kategorii 8 na opis Fraud VOIP
            "9": "🔓 Open Proxy",                                                                   # Mapowanie kategorii 9 na opis Open Proxy
            "10": "📧 Web Spam",                                                                    # Mapowanie kategorii 10 na opis Web Spam
            "11": "📧 Email Spam",                                                                  # Mapowanie kategorii 11 na opis Email Spam
            "12": "📝 Blog Spam",                                                                   # Mapowanie kategorii 12 na opis Blog Spam
            "13": "🛡️ VPN IP",                                                                      # Mapowanie kategorii 13 na opis VPN IP
            "14": "🔍 Port Scan",                                                                   # Mapowanie kategorii 14 na opis Port Scan
            "15": "💻 Hacking",                                                                     # Mapowanie kategorii 15 na opis Hacking
            "16": "💉 SQL Injection",                                                               # Mapowanie kategorii 16 na opis SQL Injection
            "17": "🎭 Spoofing",                                                                    # Mapowanie kategorii 17 na opis Spoofing
            "18": "🔑 Brute Force",                                                                 # Mapowanie kategorii 18 na opis Brute Force
            "19": "🤖 Bad Web Bot",                                                                 # Mapowanie kategorii 19 na opis Bad Web Bot
            "20": "🏠 Exploited Host",                                                              # Mapowanie kategorii 20 na opis Exploited Host
            "21": "🕸️ Web App Attack",                                                              # Mapowanie kategorii 21 na opis Web App Attack
            "22": "🔑 SSH",                                                                         # Mapowanie kategorii 22 na opis SSH
            "23": "🛡️ IoT Targeted",                                                                # Mapowanie kategorii 23 na opis IoT Targeted
            
        }  # Zakończenie definicji słownika mapping
        return mapping.get(str(category_number), "Unknown Category")                  # Zwróć opis kategorii lub "Unknown Category" jeśli nie znaleziono

    def get_ip_reputation(self, ip, days_to_check=30):                                # Deklaracja metody pobierającej reputację IP z domyślnym okresem 30 dni
        
        url = "https://api.abuseipdb.com/api/v2/check"                                # Definicja URL endpointu API AbuseIPDB (poprawny format)
        headers = {"Accept": "application/json", "Key": self.api_key}                 # Definicja nagłówków HTTP z kluczem API i typem odpowiedzi JSON
        params = {"maxAgeInDays": days_to_check, "verbose": "True", "ipAddress": ip}  # Definicja parametrów zapytania: wiek raportów, tryb verbose, adres IP

        try:                                                                          # Rozpoczęcie bloku try do obsługi wyjątków sieciowych
            response = requests.get(url, headers=headers, params=params)              # Wykonaj żądanie GET do API z nagłówkami i parametrami
            response.raise_for_status()                                               # Podnieś wyjątek jeśli status HTTP odpowiedzi wskazuje na błąd (4xx/5xx)
            data = response.json()["data"]                                            # Sparsuj odpowiedź JSON i wyodrębnij klucz "data" z wynikiem

            # List comprehension do ekstrakcji unikalnych kategorii z listy raportów
            categories = [                                                            # Rozpoczęcie tworzenia listy categories
                self.extract_abuse_ipdb_category(c)                                   # Dla każdej kategorii c wywołaj metodę mapującą na opis
                for report in data.get("reports", [])                                 # Iteruj po raportach z danych API (domyślnie pusta lista jeśli brak)
                for c in report.get("categories", [])                                 # Iteruj po kategoriach w każdym raporcie (domyślnie pusta lista jeśli brak)
            ]                                                                         # Zakończenie list comprehension

            return {                                                                  # Rozpoczęcie zwracania słownika z wynikami
                "total_reports": data.get("totalReports", 0),                         # Pobierz liczbę raportów lub 0 jeśli klucz nie istnieje
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0),        # Pobierz wynik pewności nadużycia lub 0
                "country": data.get("countryCode", "N/A"),                            # Pobierz kod kraju lub "N/A" jeśli brak danych
                "isp": data.get("isp", "N/A"),                                        # Pobierz nazwę ISP lub "N/A" jeśli brak danych
                "is_whitelisted": data.get("isWhitelisted", False),                   # Pobierz flagę whitelisted lub False domyślnie
                "is_tor": data.get("isTor", False),                                   # Pobierz flagę Tor lub False domyślnie
                "categories": list(set(categories)) if categories else ["None"]       # Zwróć unikalne kategorie jako listę lub ["None"] jeśli puste
            }                                                                         # Zakończenie zwracania słownika z wynikami
        except requests.exceptions.RequestException as e:                             # Obsługa wyjątków związanych z żądaniami HTTP
            print(f"{Colors.BrightRed}X AbuseIPDB Error: {e}{Colors.Reset}")          # Wyświetl komunikat błędu z AbuseIPDB w czerwonym kolorze
            return None                                                               # Zwróć None w przypadku błędu

# Definicja klasy VirusTotalIPChecker do obsługi interfejsu API VirusTotal
class VirusTotalIPChecker:                                                            # Deklaracja klasy
    def __init__(self, api_key):                                                      # Konstruktor klasy przyjmujący klucz API jako argument
        self.vt = Client(apikey=api_key, trust_env=True)                              # Zainicjuj klienta VirusTotal z kluczem API i zaufaniem do zmiennych środowiskowych

    def get_ip_reputation(self, ip):                                                  # Deklaracja metody pobierającej reputację IP z VirusTotal
        try:                                                                          # Rozpoczęcie bloku try do obsługi wyjątków
            result = self.vt.get_object(f"/ip_addresses/{ip}").to_dict()              # Pobierz obiekt IP z VT i przekonwertuj na słownik Python
            attributes = result.get("attributes", {})                                 # Wyodrębnij klucz "attributes" ze słownika wyniku (domyślnie pusty dict)
            stats = attributes.get("last_analysis_stats", {})                         # Wyodrębnij statystyki ostatniej analizy (domyślnie pusty dict)

            # Inicjalizacja słownika reputation_data z podstawowymi danymi reputacyjnymi
            reputation_data = {                                                       # Rozpoczęcie definicji słownika reputation_data
                "malicious": stats.get("malicious", 0),                               # Pobierz liczbę detekcji jako złośliwe lub 0
                "suspicious": stats.get("suspicious", 0),                             # Pobierz liczbę detekcji jako podejrzane lub 0
                "harmless": stats.get("harmless", 0),                                 # Pobierz liczbę detekcji jako nieszkodliwe lub 0
                "undetected": stats.get("undetected", 0),                             # Pobierz liczbę detekcji jako niewykryte lub 0
                "country": attributes.get("country", "N/A"),                          # Pobierz kraj lub "N/A" jeśli brak danych
                "asn": attributes.get("as_owner", "N/A"),                             # Pobierz właściciela ASN lub "N/A" jeśli brak danych
                "total_scans": sum(stats.values()),                                   # Oblicz całkowitą liczbę skanów sumując wszystkie wartości statystyk
                "vendor_detections": {},                                              # Zainicjuj pusty słownik na detekcje od poszczególnych vendorów
                "popular_threat_label": "N/A",                                        # Zainicjuj etykietę zagrożenia jako "N/A"
                "relations": {}                                                       # Zainicjuj pusty słownik na relacje/powiązania
            }                                                                         # Zakończenie definicji słownika reputation_data

            # Iteracja po wynikach analizy od poszczególnych dostawców silników AV
            detections = attributes.get("last_analysis_results", {})                                          # Pobierz słownik wyników analizy od vendorów
            for vendor, data in detections.items():                                                           # Iteruj po parach vendor-dane w słowniku detections
                if data.get("category") in ["malicious", "suspicious"]:                                       # Sprawdź czy kategoria to malicious lub suspicious
                    reputation_data["vendor_detections"][vendor.upper()] = data.get("result", "N/A")          # Dodaj detekcję do słownika z nazwą vendora wielkimi literami

            # Pobranie i przypisanie popularnej etykiety zagrożenia jeśli istnieje
            threat_label = attributes.get("popular_threat_classification", {}).get("suggested_threat_label")  # Wyodrębnij sugerowaną etykietę zagrożenia z zagnieżdżonej struktury
            if threat_label:                                                                                  # Sprawdź czy etykieta zagrożenia istnieje (nie jest None/pusta)
                reputation_data["popular_threat_label"] = threat_label                                        # Przypisz etykietę do słownika wyników

            # Pobranie relacji/powiązań dla adresu IP
            relations = self.get_ip_relations(ip)                                                             # Wywołaj metodę get_ip_relations aby pobrać powiązane obiekty
            if relations:                                                                                     # Sprawdź czy metoda zwróciła jakieś dane relacji
                reputation_data["relations"] = relations                                                      # Dodaj relacje do słownika wyników

            return reputation_data                                                                            # Zwróć kompletny słownik z danymi reputacyjnymi

        except Exception as e:                                                                                # Obsługa dowolnego wyjątku podczas pobierania danych z VT
            print(f"{Colors.BrightRed}X VirusTotal Error: {e}{Colors.Reset}")                                 # Wyświetl komunikat błędu z VirusTotal w czerwonym kolorze
            return None                                                                                       # Zwróć None w przypadku błędu

    def get_ip_relations(self, ip):                                                                           # Deklaracja metody pobierającej relacje/powiązania dla adresu IP
        try:                                                                                                  # Rozpoczęcie bloku try do obsługi wyjątków
            relations = self.vt.get_object(f"/ip_addresses/{ip}/relations").to_dict()                         # Pobierz obiekt relacji dla IP i przekonwertuj na dict
            data = relations.get("data", [])                                                                  # Wyodrębnij listę danych z klucza "data" (domyślnie pusta lista)
            threat_labels = set()                                                                             # Zainicjuj pusty zbiór do przechowywania unikalnych etykiet zagrożeń
            av_detections = {}                                                                                # Zainicjuj pusty słownik do przechowywania detekcji AV z relacji

            for item in data:                                                                                 # Iteruj po każdym elemencie w liście danych relacji
                label = item.get("attributes", {}).get("popular_threat_label")                                # Wyodrębnij etykietę zagrożenia z zagnieżdżonych atrybutów
                if label:                                                                                     # Sprawdź czy etykieta istnieje
                    threat_labels.add(label)                                                                  # Dodaj etykietę do zbioru unikalnych etykiet

                results = item.get("attributes", {}).get("last_analysis_results", {})                         # Pobierz wyniki analizy z atrybutów elementu
                for vendor, info in results.items():                                                          # Iteruj po wynikach od poszczególnych vendorów
                    if info.get("category") in ["malicious", "suspicious"]:                                   # Sprawdź czy kategoria to malicious lub suspicious
                        av_detections[vendor.upper()] = info.get("result", "N/A")                             # Dodaj detekcję do słownika z nazwą vendora wielkimi literami

            return {                                                                                          # Rozpoczęcie zwracania słownika z wynikami relacji
                "threat_labels": list(threat_labels),                                                         # Konwertuj zbiór etykiet na listę i zwróć
                "av_detections": av_detections                                                                # Zwróć słownik z detekcjami AV
            }                                                                                                 # Zakończenie zwracania słownika z wynikami relacji
        except:                                                                                               # Obsługa dowolnego wyjątku (ogólny except bez specyfikacji)
            return None                                                                                       # Zwróć None w przypadku błędu przy pobieraniu relacji

    def close(self):                                                                                          # Deklaracja metody zamykającej połączenie z klientem VT
        self.vt.close()                                                                                       # Wywołaj metodę close() klienta VirusTotal aby zwolnić zasoby

# Definicja funkcji get_ipinfo_reputation do pobierania danych geolokalizacyjnych z IPInfo
def get_ipinfo_reputation(ip, api_key):                                                                       # Deklaracja funkcji przyjmującej IP i klucz API jako argumenty

    url = f"https://ipinfo.io/{ip}/json"                                                                      # Skonstruuj URL zapytania do API IPInfo (poprawny format bez spacji)
    headers = {"Authorization": f"Bearer {api_key}"}                                                          # Skonstruuj nagłówek Authorization z kluczem API w formacie Bearer
    try:                                                                                                      # Rozpoczęcie bloku try do obsługi wyjątków
        response = requests.get(url, headers=headers)                                                         # Wykonaj żądanie GET do API IPInfo z nagłówkiem autoryzacji
        response.raise_for_status()                                                                           # Podnieś wyjątek jeśli status HTTP odpowiedzi wskazuje na błąd
        data = response.json()                                                                                # Sparsuj odpowiedź JSON do słownika Python
        return f"Hostname: {data.get('hostname', 'N/A')}, 🌍 Country: {data.get('country', 'N/A')}"           # Zwróć sformatowany string z hostname i krajem
    except:                                                                                                   # Obsługa dowolnego wyjątku (ogólny except)
        return "N/A"                                                                                          # Zwróć "N/A" w przypadku błędu

# Definicja funkcji process_ip do przetwarzania pojedynczego adresu IP i generowania raportów
def process_ip(ip, config):         

    # Walidacja IP przed wykonaniem zapytań API
    if not is_valid_ip(ip):                                                                                   # Sprawdź czy IP ma poprawny format IPv4
        print(f"{Colors.BrightRed}X Niepoprawny format IP: {ip} – pominięto{Colors.Reset}")                   # Wyświetl ostrzeżenie w czerwonym kolorze
        return None                                                                                           # Zwróć None aby pominąć generowanie raportu dla niepoprawnego IP

    abuse_checker = AbuseIPDBChecker(config["abuseipdb"])                                                     # Utwórz instancję AbuseIPDBChecker z kluczem API z configu
    vt_checker = VirusTotalIPChecker(config["virustotal"])                                                    # Utwórz instancję VirusTotalIPChecker z kluczem API z configu

    abuse_data = abuse_checker.get_ip_reputation(ip)                                                          # Pobierz dane reputacji z AbuseIPDB dla danego IP
    vt_data = vt_checker.get_ip_reputation(ip)                                                                # Pobierz dane reputacji z VirusTotal dla danego IP
    ipinfo_data = get_ipinfo_reputation(ip, config["ipinfo"])                                                 # Pobierz dane geolokalizacyjne z IPInfo dla danego IP
    vt_checker.close()                                                                                        # Zamknij połączenie z klientem VirusTotal aby zwolnić zasoby

    result = f"🚨 Reputacja IP:\n{ip}\n"                                                                      # Zainicjuj string raportu tekstowego z nagłówkiem i adresem IP
    json_result = {"ip": ip, "timestamp": datetime.now().isoformat()}                                         # Zainicjuj słownik raportu JSON z IP i znacznikiem czasu ISO

    # Budowanie sekcji raportu dla VirusTotal jeśli dane zostały pobrane pomyślnie
    if vt_data:                                                                                               # Sprawdź czy vt_data nie jest None
        result += f"""\n⚡ VirusTotal Reputacja:
=========================================>> 
🔍 Liczba skanów: {vt_data['total_scans']}
☣️ Złośliwe: {vt_data['malicious']}
⚠ Podejrzane: {vt_data['suspicious']}
✅ Nieszkodliwe: {vt_data['harmless']}
❓ Niewykryte: {vt_data['undetected']}
🌐 Kraj: {vt_data['country']}
🏢 ASN: {vt_data['asn']}

"""                                                                                                           # Zakończenie multi-line stringa z danymi VT
        if vt_data["popular_threat_label"] != "N/A":                                                          # Sprawdź czy etykieta zagrożenia jest ustawiona
            result += f"🏷️ Popular threat label: {vt_data['popular_threat_label']}\n"                         # Dodaj etykietę zagrożenia do raportu

        if vt_data["vendor_detections"]:                                                                      # Sprawdź czy są jakieś detekcje od vendorów
            result += "\n🛡️ Detekcje przez dostawców:\n"                                                      # Dodaj nagłówek sekcji detekcji vendorów
            for vendor, detection in vt_data["vendor_detections"].items():                                    # Iteruj po detekcjach vendorów
                result += f"- {vendor}: {detection}\n"                                                        # Dodaj każdą detekcję w formacie "- Vendor: wynik" do raportu

        relations = vt_data.get("relations", {})                                                              # Pobierz słownik relacji z danych VT (domyślnie pusty dict)
        if relations and relations.get("threat_labels"):                                                      # Sprawdź czy relacje istnieją i mają etykiety zagrożeń
            result += "\n🧬 Zagrożenia powiązane (Relations):\n"                                              # Dodaj nagłówek sekcji powiązanych zagrożeń
            result += "- " + ", ".join(relations["threat_labels"]) + "\n"                                     # Dodaj listę etykiet zagrożeń oddzielonych przecinkami

        json_result["virustotal"] = vt_data                                                                   # Dodaj pełne dane VT do słownika raportu JSON

    else:                                                                                                     # Obsługa przypadku gdy pobieranie danych VT się nie powiodło
        result += "\nVirusTotal: ❌ Błąd pobierania danych\n"                                                 # Dodaj komunikat błędu do raportu tekstowego

    # Budowanie sekcji raportu dla AbuseIPDB jeśli dane zostały pobrane pomyślnie
    if abuse_data:                                                                                            # Sprawdź czy abuse_data nie jest None
        categories_str = "\n - " + "\n - ".join(abuse_data["categories"])                                     # Połącz listę kategorii w string z myślnikami i nowymi liniami
        result += f"""\n🚫 AbuseIPDB Reputacja:
=========================================>>
📢 Liczba zgłoszeń: {abuse_data['total_reports']}
📈 Wynik pewności: {abuse_data['abuse_confidence_score']}%
🌍 Kraj: {abuse_data['country']}
🌐 ISP: {abuse_data['isp']}
📂 Kategorie: {categories_str}
"""                                                                                                           # Zakończenie multi-line stringa z danymi AbuseIPDB
        json_result["abuseipdb"] = abuse_data                                                                 # Dodaj pełne dane AbuseIPDB do słownika raportu JSON

    # Dodanie sekcji IPInfo do raportu
    result += f"\n📍 IPInfo: {ipinfo_data}\n"                                                                 # Dodaj dane z IPInfo do raportu tekstowego
    json_result["ipinfo"] = ipinfo_data                                                                       # Dodaj dane z IPInfo do słownika raportu JSON

    # Zapis raportu tekstowego do pliku
    with open(f"{ip}_raport.txt", "w", encoding="utf-8") as f:                                                # Otwórz plik do zapisu z nazwą zawierającą IP i encoding UTF-8
        f.write(result)                                                                                       # Zapisz zawartość stringa result do pliku

    # Zapis raportu JSON do pliku
    with open(f"{ip}_raport.json", "w", encoding="utf-8") as f:                                               # Otwórz plik JSON do zapisu z nazwą zawierającą IP i encoding UTF-8
        json.dump(json_result, f, indent=4, ensure_ascii=False)                                               # Zapisz słownik json_result do pliku z wcięciami i obsługą Unicode

    print(f"{Colors.BrightGreen}✅ Raporty dla {ip} zostały wygenerowane.{Colors.Reset}")                     # Wyświetl komunikat sukcesu w zielonym kolorze
    return result                                                                                             # Zwróć string raportu tekstowego

# Definicja głównej funkcji programu main
def main():                                                                                                   # Deklaracja funkcji main bez argumentów
    print(ASCII_BANNER)                                                                                       # Wyświetl banner ASCII na początku działania programu

    if len(sys.argv) != 2:                                                                                    # Sprawdź czy liczba argumentów wiersza poleceń jest różna od 2 (nazwa skryptu + 1 argument)
        print(f"{Colors.BrightRed}Użycie: python bulk_ip.py <lista_ip.txt>{Colors.Reset}")                    # Wyświetl komunikat o poprawnym użyciu w czerwonym kolorze
        sys.exit(1)                                                                                           # Zakończ program z kodem błędu 1

    config = load_config()                                                                                    # Wczytaj konfigurację z pliku JSON wywołując funkcję load_config
    txt_file = sys.argv[1]                                                                                    # Przypisz pierwszy argument wiersza poleceń (poza nazwą skryptu) do zmiennej txt_file

    try:                                                                                                      # Rozpoczęcie bloku try do obsługi wyjątków przy odczycie pliku
        with open(txt_file, "r") as f:                                                                        # Otwórz plik z listą IP w trybie do odczytu jako f
            ips = [line.strip() for line in f if line.strip()]                                                # Wczytaj niepuste linie, usuń białe znaki z końców i stwórz listę IP
    except FileNotFoundError:                                                                                 # Obsługa wyjątku gdy plik z listą IP nie istnieje
        print(f"{Colors.BrightRed}Błąd: Nie znaleziono pliku {txt_file}{Colors.Reset}")                       # Wyświetl komunikat błędu w czerwonym kolorze
        sys.exit(1)                                                                                           # Zakończ program z kodem błędu 1

    print(f"{Colors.Cyan}[*] Wczytano {len(ips)} adresów IP. Rozpoczynam przetwarzanie...{Colors.Reset}\n")   # Wyświetl informację o liczbie wczytanych IP w kolorze cyjan

    # Pętla przetwarzająca każdy adres IP z listy
    for i, ip in enumerate(ips):                                                                              # Iteruj po liście ips z indeksem i i wartością ip
        print(f"{Colors.BrightYellow}[{i+1}/{len(ips)}] Przetwarzanie: {ip}{Colors.Reset}")                   # Wyświetl postęp przetwarzania w żółtym kolorze
        process_ip(ip, config)                                                                                # Wywołaj funkcję process_ip dla bieżącego adresu IP i konfiguracji

        # Dodanie opóźnienia między zapytaniami aby uniknąć przekroczenia limitów API (rate limiting)
        if i < len(ips) - 1:                                                                                  # Sprawdź czy nie jest to ostatni element w liście (aby nie czekać po ostatnim IP)
            print(f"{Colors.Gray}⏳ Oczekiwanie 60s (Rate Limit)...{Colors.Reset}")                           # Wyświetl komunikat o oczekiwaniu w szarym kolorze
            time.sleep(60)                                                                                    # Wstrzymaj wykonanie programu na 60 sekund

    print(f"\n{Colors.BrightGreen}🏁 Skanowanie zakończone.{Colors.Reset}")                                   # Wyświetl komunikat końcowy sukcesu w zielonym kolorze

# Warunek uruchamiający funkcję main tylko gdy skrypt jest wykonywany bezpośrednio (nie importowany)
if __name__ == "__main__":                                                                                    # Sprawdź czy moduł jest uruchamiany jako główny program
    main()                                                                                                    # Wywołaj funkcję main aby rozpocząć działanie programu
