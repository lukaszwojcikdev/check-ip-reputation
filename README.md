```markdown
  ____ _               _    ___ ____  
 / ___| |__   ___  ___| | _|_ _|  _ \ 
| |   | '_ \ / _ \/ __| |/ /| || |_) |
| |___| | | |  __/ (__|   < | ||  __/ 
 \____|_| |_|\___|\___|_|\_\___|_|    

# 🚨 CHECK_IP – Bulk IP Reputation Scanner
```
> **Wersja:** 1.2 | **Autor:** Łukasz Wójcik | **Rok:** 2026

[![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)](https://www.python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen)](#)

Narzędzie CLI do **masowego sprawdzania reputacji adresów IP** przy użyciu  **AbuseIPDB**, **VirusTotal** i **IPInfo**. 

Generuje czytelne raporty w formacie tekstowym i JSON – idealne do analizy bezpieczeństwa, SOC, pentestów i automatyzacji.

---

## ✨ Funkcje

✅ **Multi-API Integration** – pobieranie danych z AbuseIPDB, VirusTotal i IPInfo  
✅ **Bulk Processing** – przetwarzanie listy adresów IP z pliku `.txt`  
✅ **Dual Output** – generowanie raportów w formacie `.txt` (czytelny) i `.json` (parsowalny)  
✅ **Kolorowe wyjście CLI** – estetyczny terminal z ASCII bannerem i kodami ANSI  
✅ **Mapowanie kategorii AbuseIPDB** – czytelne opisy zamiast numerów kategorii  
✅ **Detekcje vendor-specific** – wyświetlanie tylko złośliwych/podejrzanych wyników z VT  
✅ **Obsługa relacji VirusTotal** – powiązane zagrożenia, domeny, pliki  
✅ **Geolokalizacja i hostname** – dzięki IPInfo  
✅ **Automatyczne opóźnienia** – ochrona przed rate limitami darmowych API  
✅ **Obsługa błędów** – graceful fallback przy problemach z API  

---

## 🛠 Wymagania

- Python 3.7+
- Pliki z listą IP (jeden adres IP na linię)
- Klucze API dla:
  - [AbuseIPDB](https://www.abuseipdb.com/)
  - [VirusTotal](https://www.virustotal.com/)
  - [IPInfo](https://ipinfo.io/)

### Dependencje Python

```bash
pip install requests vt-py
```

Lub z `requirements.txt`:

```txt
requests>=2.28.0
vt-py>=0.18.0
```

---

## 📦 Instalacja

```bash
# 1. Sklonuj repozytorium
git clone https://github.com/lukaszwojcikdev/check-ip-reputation
cd check-ip

# 2. Zainstaluj zależności
pip install -r requirements.txt

# 3. Skonfiguruj klucze API (patrz sekcja Konfiguracja)
cp config.example.json config.json
# Edytuj config.json i wstaw swoje klucze

# 4. Uruchom narzędzie
python check_ip.py lista_ip.txt
```

---

## ⚙️ Konfiguracja

Utwórz plik `config.json` w katalogu projektu:

```json
{
  "abuseipdb": "TWÓJ_KLUCZ_ABUSEIPDB",
  "virustotal": "TWÓJ_KLUCZ_VIRUSTOTAL",
  "ipinfo": "TWÓJ_KLUCZ_IPINFO"
}
```

> 🔐 **Bezpieczeństwo**: Nigdy nie commituj pliku `config.json` z prawdziwymi kluczami! Dodaj go do `.gitignore`.

### Przykładowy `config.example.json`:

```json
{
  "abuseipdb": "your_abuseipdb_key_here",
  "virustotal": "your_virustotal_key_here",
  "ipinfo": "your_ipinfo_key_here"
}
```

---

## 🚀 Użycie

### Podstawowe uruchomienie

```bash
python check_ip.py lista_ip.txt
```

### Wynik

```javascript
   ____ _               _    ___ ____
 / ___| |__   ___  ___| | _|_ _|  _ \
| |   | '_ \ / _ \/ __| |/ /| || |_) |
| |___| | | |  __/ (__|   < | ||  __/
 \____|_| |_|\___|\___|_|\_\___|_|

> CHECK_IP - Bulk Reputation Scanner
> (c) 2026 by Łukasz Wójcik  version 1.3
> GitHub: https://github.com/lukaszwojcikdev/check-ip-reputation
> Usage: check_ip.py <LIST_IP_FILE.txt>

[*] Wczytano 3 adresów IP. Rozpoczynam przetwarzanie...

[1/3] Przetwarzanie: 1.1.1.1
✅ Raporty dla 1.1.1.1 zostały wygenerowane.
⏳ Oczekiwanie 60s (Rate Limit)...
[2/3] Przetwarzanie: 8.8.8.8
✅ Raporty dla 8.8.8.8 zostały wygenerowane.
⏳ Oczekiwanie 60s (Rate Limit)...
[3/3] Przetwarzanie: 9.9.9.9
✅ Raporty dla 9.9.9.9 zostały wygenerowane.

🏁 Skanowanie zakończone.
```

### Format pliku wejściowego (`lista_ip.txt`)

```
1.1.1.1
8.8.8.8
9.9.9.9
# Komentarze i puste linie są ignorowane
```

### Wyjście

Dla każdego adresu IP narzędzie generuje dwa pliki:
- `<ip>_raport.txt` – czytelny raport w terminalu
- `<ip>_raport.json` – strukturalny JSON do dalszej analizy

---

## 📄 Przykład wyjścia (TXT)

```
🚨 Reputacja IP:
8.8.8.8

⚡ VirusTotal Reputacja:
=========================================>>
🔍 Liczba skanów: 89
☣️ Złośliwe: 0
⚠ Podejrzane: 0
✅ Nieszkodliwe: 89
❓ Niewykryte: 0
🌐 Kraj: US
🏢 ASN: Google LLC

🚫 AbuseIPDB Reputacja:
=========================================>>
📢 Liczba zgłoszeń: 0
📈 Wynik pewności: 0%
🌍 Kraj: US
🌐 ISP: Google LLC
📂 Kategorie: 
 - None

📍 IPInfo: Hostname: dns.google, 🌍 Country: US
```

---

## 🗂 Struktura raportu JSON

```json
{
  "ip": "8.8.8.8",
  "timestamp": "2025-03-19T12:34:56.789012",
  "virustotal": {
    "malicious": 0,
    "suspicious": 0,
    "harmless": 89,
    "undetected": 0,
    "country": "US",
    "asn": "Google LLC",
    "total_scans": 89,
    "vendor_detections": {},
    "popular_threat_label": "N/A",
    "relations": {}
  },
  "abuseipdb": {
    "total_reports": 0,
    "abuse_confidence_score": 0,
    "country": "US",
    "isp": "Google LLC",
    "is_whitelisted": false,
    "is_tor": false,
    "categories": ["None"]
  },
  "ipinfo": "Hostname: dns.google, 🌍 Country: US"
}
```

---

## ⏱ Rate Limiting

Narzędzie automatycznie dodaje **60-sekundowe opóźnienie** między zapytaniami, aby uniknąć przekroczenia limitów darmowych planów API:

| Usługa | Limit darmowy | Uwagi |
|--------|--------------|--------|
| AbuseIPDB | 1 000 zapytań/dzień | `maxAgeInDays`, `verbose` włączone |
| VirusTotal | 4 zapytania/min (Public API) | Używany oficjalny klient `vt-py` |
| IPInfo | 50 000 zapytań/miesiąc | Wymaga klucza dla większych limitów |

> 💡 **Porada**: Dla dużych list IP rozważ wykupienie planów premium lub uruchomienie skryptu w trybie wsadowym z dłuższymi przerwami.

---

## 🔑 Uzyskanie kluczy API

1. **AbuseIPDB**: https://www.abuseipdb.com/api
2. **VirusTotal**: https://www.virustotal.com/gui/join-us
3. **IPInfo**: https://ipinfo.io/signup

Po rejestracji skopiuj klucze do `config.json`.

---

## 🤝 Wkład w projekt

Pull requesty są mile widziane! Przed wysłaniem:

1. Fork repozytorium
2. Utwórz branch (`git checkout -b feature/NowaFunkcja`)
3. Commit zmian (`git commit -m 'Dodaj nową funkcję'`)
4. Push (`git push origin feature/NowaFunkcja`)
5. Otwórz Pull Request

Proszę o dodanie testów i aktualizację dokumentacji dla nowych funkcji.

---

## 📜 Licencja

Projekt dostępny na licencji **MIT** – zobacz plik [LICENSE](LICENSE) po szczegóły.

---

## 🧑‍💻 Autor

**Łukasz Wójcik**  
🐙 GitHub: [lukaszwojcikdev](https://github.com/lukaszwojcikdev)  
🔗 LinkedIn: [profil_linkedin](https://www.linkedin.com/in/lukasz-michal-wojcik)

🌐 Website: [strona_domowa](https://lukaszwojcik.eu)

> 💬 *"Bezpieczeństwo to proces, nie produkt."*

---

> 🌟 **Podoba Ci się projekt?** Pomóż w rozwoju:
⭐ Daj gwiazdkę na GitHubie – to motywuje!
🐛 Zgłoś błąd lub propozycję w Issues
💻 Wyślij PR z poprawką lub nową funkcją
📢 Udostępnij w społecznościach security / dev
Każdy wkład się liczy! 🙏
```

## ⚠️ Disclaimer

Narzędzie przeznaczone jest wyłącznie do **legalnych celów badawczych, edukacyjnych i audytowych**.

**Oprogramowanie dostarczane jest "takie, jakie jest" (AS IS)** bez jakichkolwiek gwarancji,
wyraźnych lub dorozumianych, w tym gwarancji przydatności do określonego celu lub braku błędów.

Autor **nie ponosi odpowiedzialności** za:
- Jakiekolwiek szkody wynikające z użycia narzędzia;
- Błędy, luki bezpieczeństwa lub niezawodność oprogramowania;
- Nieprawidłowe użycie w sposób niezgodny z prawem;
- Skutki wynikające z nieodpowiednich danych wejściowych i wyjściowych;

**Użytkownik używa na własne ryzyko i odpowiedzialność.**



