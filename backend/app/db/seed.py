from sqlalchemy import select

from app.db.models import ScanProfile

QUICK_PORTS = [
    22,
    25,
    53,
    80,
    110,
    143,
    443,
    465,
    587,
    993,
    995,
    1433,
    3306,
    3389,
    5432,
    6379,
    8000,
    8080,
    8443,
    9200,
    27017,
]
STANDARD_PORTS = sorted(
    set(
        QUICK_PORTS
        + [
            21,
            23,
            81,
            88,
            111,
            135,
            139,
            389,
            445,
            512,
            513,
            514,
            636,
            853,
            873,
            989,
            990,
            1080,
            1521,
            2049,
            2375,
            2376,
            3000,
            5000,
            5601,
            5900,
            6443,
            8008,
            8081,
            8888,
            9000,
            9090,
            9443,
            11211,
        ]
    )
)


def seed_profiles(db):
    for name, ports, description in [
        ("Quick", QUICK_PORTS, "Common TCP services; 21 ports"),
        ("Standard", STANDARD_PORTS, "Broader regular monitoring; bounded TCP coverage"),
    ]:
        if not db.scalar(select(ScanProfile).where(ScanProfile.name == name)):
            db.add(ScanProfile(name=name, ports=ports, description=description))
    db.commit()
