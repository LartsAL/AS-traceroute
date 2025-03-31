import re
import platform
import socket
import subprocess
from ipwhois import IPWhois
from prettytable import PrettyTable
import pycountry
import requests


def check_internet_connection() -> bool:
    """Проверяет наличие интернет-соединения."""
    try:
        requests.get("http://www.google.com", timeout=5)
        return True
    except (requests.ConnectionError, requests.Timeout):
        return False


def resolve_domain(target: str) -> str:
    if re.match(r"(?:\d{1,3}\.){3}\d{1,3}", target):
        return target

    try:
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror:
        raise RuntimeError(f"Не удалось разрешить доменное имя: {target}")
    except Exception as e:
        raise RuntimeError(f"Ошибка при разрешении доменного имени: {e}")


def get_trace_command(target: str) -> list[str]:
    """Выбирает команду для трассировки в зависимости от ОС (Windows/Linux)."""
    system = platform.system().lower()

    if system == "windows":
        return ["tracert", "-d", "-w", "1000", "-h", "30", target]
    elif system == "linux":
        return ["traceroute", "-n", "-q", "1", "-w", "1", "-m", "30", target]
    else:
        raise OSError(f"Неподдерживаемая ОС: {system}")


def parse_trace_output(output: str) -> list[str]:
    """Извлекает IPv4 адреса из вывода трассировки."""
    pattern = r"(?:\d{1,3}\.){3}\d{1,3}"  # x.x.x.x

    ips = []

    for line in output.split("\n"):
        match = re.search(pattern, line)
        if match:
            ip = match.group(0)
            ips.append(ip)

    # Пропуск IP в заголовке вывода
    ips = ips[1:]

    return ips


def is_private_ip(ip: str) -> bool:
    """Определяет серые IPv4 адреса."""
    octets = list(map(int, ip.split(".")))
    return (
        (octets[0] == 10)  # 10.0.0.0/8
        or (octets[0] == 172 and 16 <= octets[1] <= 31)  # 172.16.0.0/12
        or (octets[0] == 192 and octets[1] == 168)  # 192.168.0.0/16
    )


def get_ip_info(ip: str) -> dict:
    """Получает информацию об AS, стране и провайдере."""
    default = "-"

    if is_private_ip(ip):
        return {"asn": default, "country": default, "provider": default}

    try:
        whois = IPWhois(ip).lookup_rdap()

        asn = whois.get("asn", default)
        country_code = whois.get("asn_country_code", default)
        provider = whois.get("asn_description", default)

        country = pycountry.countries.get(alpha_2=country_code)

        return {
            # Whois даёт NA, если неизвестно, но для красоты меняем на default (-)
            "asn": asn if not asn == "NA" else default,
            "country": country.name if country else country_code,
            "provider": provider if not provider == "NA" else default,
        }
    except Exception as e:
        print(f"Ошибка WHOIS для {ip}: {e}")
        return {"asn": default, "country": default, "provider": default}


def print_results(ips: list[str]) -> None:
    """Выводит таблицу с результатами трассировки."""
    table = PrettyTable()
    table.field_names = ["№", "IP", "ASN", "Страна", "Провайдер"]

    for idx, ip in enumerate(ips, 1):
        info = get_ip_info(ip)
        table.add_row([idx, ip, info["asn"], info["country"], info["provider"]])

    print(table)


def main():
    try:
        if not check_internet_connection():
            print("Ошибка: Нет подключения к интернету.")
            return

        target = input("Введите домен или IPv4: ").strip()
        if not target:
            print("Ошибка: Необходимо указать домен или IPv4 адрес.")
            return

        target_ip = resolve_domain(target)

        if is_private_ip(target_ip):
            print("Ошибка: Невозможно выполнить трассировку для серых IP-адресов.")
            return

        trace_cmd = get_trace_command(target_ip)

        try:
            result = subprocess.run(
                trace_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=60,
            )
        except subprocess.TimeoutExpired:
            print("Ошибка: Трассировка заняла слишком много времени.")
            return

        if result.stderr:
            print(f"Ошибка: {result.stderr}")
            return

        ips = parse_trace_output(result.stdout)
        if not ips:
            print("Ошибка: Не удалось извлечь IP-адреса.")
            return

        print_results(ips)
    except Exception as e:
        print(f"Ошибка: {e}")


if __name__ == "__main__":
    main()
