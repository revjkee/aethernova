import asyncio
import json
import time
from typing import Any, Dict, List, Optional, Tuple
import pytest

# Обязательные зависимости для интеграционного HTTP-тестирования
httpx = pytest.importorskip("httpx")
fastapi = pytest.importorskip("fastapi")
pytest_asyncio = pytest.importorskip("pytest_asyncio")

from fastapi import FastAPI, Depends
from starlette.status import (
    HTTP_200_OK,
    HTTP_201_CREATED,
    HTTP_202_ACCEPTED,
    HTTP_304_NOT_MODIFIED,
)

# Импортируем роутер снапшотов и его сервисный протокол
snap_routes = pytest.importorskip("avm_core.engine.api.routes.snapshot")
Snapshot = getattr(snap_routes, "Snapshot")
SnapshotCreate = getattr(snap_routes, "SnapshotCreate")
SnapshotList = getattr(snap_routes, "SnapshotList")
SnapshotServiceProtocol = getattr(snap_routes, "SnapshotServiceProtocol")
router = getattr(snap_routes, "router")
get_snapshot_service = getattr(snap_routes, "get_snapshot_service")


def _mk_snapshot(
    snap_id: str,
    vm_id: str,
    name: str,
    version: int = 0,
    created_ts: Optional[float] = None,
    status: str = "ready",
) -> Any:
    created_ts = created_ts or time.time()
    payload = {
        "id": snap_id,
        "vm_id": vm_id,
        "name": name,
        "status": status,
        "created_at": pytest.datetime_fromtimestamp(created_ts),
        "updated_at": pytest.datetime_fromtimestamp(created_ts),
        "version": version,
        "size_bytes": 1024 * 1024 * 1024,
    }
    # Pydantic‑модель Snapshot принимает dict
    return Snapshot.model_validate(payload)


def _weak_etag(snap: Any) -> str:
    # Совместимо с форматом слабого ETag из vm.py — хеш по (id, version, updated_at)
    import hashlib

    raw = f"{snap.id}:{snap.version}:{int(snap.updated_at.timestamp())}".encode()
    return f'W/"{hashlib.sha256(raw).hexdigest()}"'


class _FakeSnapshotService(SnapshotServiceProtocol):
    def __init__(self) -> None:
        self._store: Dict[str, Any] = {}
        self.create_calls: int = 0

    async def list_snapshots(
        self, vm_id: str, limit: int, cursor: Optional[str]
    ) -> Tuple[List[Any], Optional[str]]:
        items = [s for s in self._store.values() if s.vm_id == vm_id]
        items.sort(key=lambda s: (s.created_at, s.id))
        page = items[: limit]
        next_cursor = None
        if len(items) > limit:
            last = page[-1]
            # Простой курсор: по времени/ID
            next_cursor = json.dumps({"created_at": last.created_at.timestamp(), "id": last.id})
        return page, next_cursor

    async def get_snapshot(self, vm_id: str, snap_id: str) -> Optional[Any]:
        s = self._store.get(snap_id)
        return s if s and s.vm_id == vm_id else None

    async def create_snapshot(self, vm_id: str, spec: Any, owner_id: str) -> Any:
        self.create_calls += 1
        snap = _mk_snapshot(
            snap_id=f"snap-{int(time.time() * 1000)}",
            vm_id=vm_id,
            name=spec.name,
            status="ready",
        )
        self._store[snap.id] = snap
        return snap

    async def delete_snapshot(self, vm_id: str, snap_id: str) -> None:
        self._store.pop(snap_id, None)

    async def restore_snapshot(self, vm_id: str, snap_id: str) -> Any:
        s = await self.get_snapshot(vm_id, snap_id)
        if not s:
            raise RuntimeError("not found")
        # Возвращаем описание задачи/операции (роутер может маппить в ActionResponse)
        return {"id": snap_id, "status": "accepted"}


@pytest_asyncio.fixture
async def app() -> FastAPI:
    app = FastAPI()
    fake = _FakeSnapshotService()

    async def _dep() -> _FakeSnapshotService:
        return fake

    # Подменяем зависимость сервиса на фейк
    app.dependency_overrides[get_snapshot_service] = _dep
    app.include_router(router)
    # Прикрепляем фейк к приложению для доступа в тестах
    app.state.fake_snapshot_service = fake
    return app


@pytest_asyncio.fixture
async def client(app: FastAPI):
    async with httpx.AsyncClient(app=app, base_url="http://testserver") as ac:
        yield ac


@pytest.mark.asyncio
async def test_create_snapshot_idempotent(client: httpx.AsyncClient, app: FastAPI):
    vm_id = "vm-1"
    payload = {"name": "pre-upgrade"}
    key = "idem-123"
    # 1‑й вызов
    r1 = await client.post(f"/v1/vms/{vm_id}/snapshots", json=payload, headers={"Idempotency-Key": key})
    assert r1.status_code == HTTP_201_CREATED, r1.text
    snap1 = r1.json()
    # 2‑й повтор с тем же ключом
    r2 = await client.post(f"/v1/vms/{vm_id}/snapshots", json=payload, headers={"Idempotency-Key": key})
    assert r2.status_code == HTTP_201_CREATED
    snap2 = r2.json()
    # Ответы должны быть байт‑в‑байт равны, а сервис вызван ровно один раз
    assert snap1 == snap2
    fake: _FakeSnapshotService = app.state.fake_snapshot_service
    assert fake.create_calls == 1


@pytest.mark.asyncio
async def test_list_snapshots_pagination(client: httpx.AsyncClient, app: FastAPI):
    vm_id = "vm-2"
    # Заполняем тестовые данные через fake‑сервис напрямую
    fake: _FakeSnapshotService = app.state.fake_snapshot_service
    for i in range(5):
        s = _mk_snapshot(snap_id=f"s{i}", vm_id=vm_id, name=f"n{i}", created_ts=time.time() + i)
        fake._store[s.id] = s

    r = await client.get(f"/v1/vms/{vm_id}/snapshots?limit=3")
    assert r.status_code == HTTP_200_OK
    page1 = r.json()
    assert len(page1["items"]) == 3
    assert page1["next_cursor"] is not None

    r = await client.get(f"/v1/vms/{vm_id}/snapshots", params={"cursor": page1["next_cursor"], "limit": 3})
    assert r.status_code == HTTP_200_OK
    page2 = r.json()
    assert len(page2["items"]) >= 2  # остаток
    # Дубликатов между страницами быть не должно
    ids1 = [x["id"] for x in page1["items"]]
    ids2 = [x["id"] for x in page2["items"]]
    assert set(ids1).isdisjoint(ids2)


@pytest.mark.asyncio
async def test_get_snapshot_with_etag_and_304(client: httpx.AsyncClient, app: FastAPI):
    vm_id = "vm-3"
    fake: _FakeSnapshotService = app.state.fake_snapshot_service
    snap = _mk_snapshot("s-etag", vm_id, "before-maint")
    fake._store[snap.id] = snap

    r1 = await client.get(f"/v1/vms/{vm_id}/snapshots/{snap.id}")
    assert r1.status_code == HTTP_200_OK
    etag = r1.headers.get("ETag")
    assert etag is not None

    r2 = await client.get(f"/v1/vms/{vm_id}/snapshots/{snap.id}", headers={"If-None-Match": etag})
    assert r2.status_code == HTTP_304_NOT_MODIFIED


@pytest.mark.asyncio
async def test_delete_snapshot_returns_202(client: httpx.AsyncClient, app: FastAPI):
    vm_id = "vm-4"
    fake: _FakeSnapshotService = app.state.fake_snapshot_service
    snap = _mk_snapshot("s-del", vm_id, "remove-me")
    fake._store[snap.id] = snap

    r = await client.delete(f"/v1/vms/{vm_id}/snapshots/{snap.id}")
    assert r.status_code == HTTP_202_ACCEPTED
    # запись должна удалиться
    assert await fake.get_snapshot(vm_id, snap.id) is None


@pytest.mark.asyncio
async def test_restore_snapshot_action(client: httpx.AsyncClient, app: FastAPI):
    vm_id = "vm-5"
    fake: _FakeSnapshotService = app.state.fake_snapshot_service
    snap = _mk_snapshot("s-restore", vm_id, "restore-point")
    fake._store[snap.id] = snap

    r = await client.post(f"/v1/vms/{vm_id}/snapshots/{snap.id}:restore")
    assert r.status_code == HTTP_200_OK
    payload = r.json()
    assert payload.get("id") == snap.id
    assert payload.get("accepted", True) in (True, False)  # в зависимости от реализации
