"""Şablon yönetimi."""


from axctl.exceptions import TemplateError
from axctl.paths import get_policy_path
from axctl.policy import save_policy


TEMPLATES = {
    "minimal": {
        "name": "Minimal Güvenlik",
        "description": "Sadece /etc/shadow koruması",
        "policy": {
            "version": 1,
            "mode": "enforcing",
            "rules": [
                {
                    "name": "tarayıcılar ssh anahtarlarını okuyamaz",
                    "subject": "firefox",
                    "object": "~/.ssh",
                    "action": "file.read",
                    "effect": "deny",
                },
                {
                    "name": "tarayıcılar /etc/shadow okuyamaz",
                    "subject": "firefox",
                    "object": "/etc/shadow",
                    "action": "file.read",
                    "effect": "deny",
                },
            ],
        },
    },
    "web-server": {
        "name": "Web Sunucusu",
        "description": "Nginx/Apache için tam koruma",
        "policy": {
            "version": 1,
            "mode": "enforcing",
            "labels": {
                "web": ["nginx", "apache2"],
            },
            "rules": [
                {
                    "name": "web sunucuları web içeriğini okur",
                    "subject": "web",
                    "object": "/var/www",
                    "action": "file.read",
                    "effect": "allow",
                },
                {
                    "name": "web sunucuları /etc/shadow okuyamaz",
                    "subject": "web",
                    "object": "/etc/shadow",
                    "action": "file.read",
                    "effect": "deny",
                },
                {
                    "name": "web sunucuları bash çalıştıramaz",
                    "subject": "web",
                    "action": "process.exec",
                    "object": "/bin/bash",
                    "effect": "deny",
                },
            ],
        },
    },
    "desktop": {
        "name": "Masaüstü",
        "description": "Masaüstü için makul varsayılanlar",
        "policy": {
            "version": 1,
            "mode": "permissive",
            "labels": {
                "browsers": ["firefox", "chromium", "google-chrome"],
            },
            "rules": [
                {
                    "name": "tarayıcılar ssh anahtarlarını okuyamaz",
                    "subject": "browsers",
                    "object": "~/.ssh",
                    "action": "file.read",
                    "effect": "deny",
                },
                {
                    "name": "tarayıcılar /etc/shadow okuyamaz",
                    "subject": "browsers",
                    "object": "/etc/shadow",
                    "action": "file.read",
                    "effect": "deny",
                },
            ],
        },
    },
    "database": {
        "name": "Veritabanı",
        "description": "Postgres/MySQL için ağ koruması",
        "policy": {
            "version": 1,
            "mode": "enforcing",
            "labels": {
                "db": ["postgres", "mysql"],
            },
            "rules": [
                {
                    "name": "veritabanları dışarı çıkamaz",
                    "subject": "db",
                    "action": "net.connect",
                    "effect": "deny",
                },
                {
                    "name": "veritabanları /etc/shadow okuyamaz",
                    "subject": "db",
                    "object": "/etc/shadow",
                    "action": "file.read",
                    "effect": "deny",
                },
            ],
        },
    },
}


def list_templates() -> list:
    """Kullanılabilir şablonları listeler."""
    return [
        {"name": key, "description": value["description"]}
        for key, value in TEMPLATES.items()
    ]


def get_template(name: str) -> dict:
    """Şablon politikasını döndürür."""
    if name not in TEMPLATES:
        raise TemplateError(f"Şablon bulunamadı: {name}. Kullanılabilir: {list(TEMPLATES.keys())}")
    return TEMPLATES[name]["policy"]


def apply_template(name: str, path: str | None = None) -> str:
    """Şablonu politika dosyasına uygular."""
    policy = get_template(name)
    if path is None:
        path = get_policy_path()
    save_policy(path, policy)
    return str(path)
