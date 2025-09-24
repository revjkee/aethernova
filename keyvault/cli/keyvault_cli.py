# keyvault/cli/keyvault_cli.py

import typer
import json
import requests
import base64
import os
from rich import print
from rich.table import Table
from getpass import getpass
from keyvault.utils.device_fingerprint import get_device_id
from keyvault.utils.context_utils import get_current_context_hash
from keyvault.core.signing_engine import sign_payload_cli
from keyvault.config.vault_config_loader import get_cli_config

app = typer.Typer(help="TeslaAI KeyVault CLI — безопасный интерфейс управления ключами")

CONFIG = get_cli_config()
API_URL = CONFIG["api_url"]
DEFAULT_HEADERS = {
    "X-Device-Fingerprint": get_device_id(),
    "X-Context-Hash": get_current_context_hash("cli-agent"),
    "X-Client-Version": "1.0.0-cli"
}


def _auth_headers():
    token = os.environ.get("KEYVAULT_TOKEN") or getpass("JWT Token: ")
    signed = sign_payload_cli(token.encode())
    headers = DEFAULT_HEADERS.copy()
    headers["Authorization"] = f"Bearer {token}"
    headers["X-Agent-Signature"] = base64.b64encode(signed).decode()
    return headers


@app.command()
def create(key: str = typer.Argument(..., help="Имя секрета"),
           value: str = typer.Option(..., prompt=True, hide_input=True),
           scope: str = typer.Option("global", help="Область секрета (по умолчанию global)")):
    """
    Создать новый секрет.
    """
    payload = {
        "key": key,
        "value": value,
        "scope": scope,
        "metadata": {"created_by": "cli"}
    }

    r = requests.post(f"{API_URL}/secret/create", headers=_auth_headers(), json=payload)
    if r.status_code == 201:
        print(f"[green]Секрет '{key}' успешно создан.[/green]")
    else:
        print(f"[red]Ошибка: {r.status_code}[/red] {r.text}")


@app.command()
def get(key: str = typer.Argument(..., help="Имя секрета")):
    """
    Получить секрет по имени.
    """
    payload = {"key": key}
    r = requests.post(f"{API_URL}/secret/get", headers=_auth_headers(), json=payload)
    if r.status_code == 200:
        data = r.json()
        print(f"[bold cyan]{data['key']}:[/bold cyan] {data['value']}")
    else:
        print(f"[red]Ошибка: {r.status_code}[/red] {r.text}")


@app.command()
def verify_token(token: str = typer.Option(..., help="Ephemeral-токен для проверки")):
    """
    Проверка временного токена.
    """
    payload = {"token": token}
    r = requests.post(f"{API_URL}/token/verify", headers=_auth_headers(), json=payload)
    if r.status_code == 200:
        print("[green]Токен действителен[/green]")
        print(json.dumps(r.json(), indent=2))
    else:
        print(f"[red]Недействительный токен:[/red] {r.status_code} {r.text}")


@app.command()
def status():
    """
    Проверка состояния API.
    """
    r = requests.get(f"{API_URL}/healthz")
    if r.status_code == 200:
        print(f"[green]API OK[/green] — {r.json()['timestamp']}")
    else:
        print(f"[red]Ошибка API:[/red] {r.status_code}")


@app.command()
def info():
    """
    Информация об активном CLI-агенте и контексте.
    """
    print("[bold]CLI Agent:[/bold] cli-agent")
    print(f"[bold]Device:[/bold] {get_device_id()}")
    print(f"[bold]Context Hash:[/bold] {get_current_context_hash('cli-agent')}")
    print(f"[bold]API Endpoint:[/bold] {API_URL}")


if __name__ == "__main__":
    app()
