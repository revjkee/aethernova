#!/usr/bin/env python3
# engine-core/engine/examples/minimal_zone/seed_world.py
"""
Deterministic minimal zone seeder for engine-core.

Goals:
- Fully deterministic output for a given seed and config (no external deps)
- Value-noise height field, biome assignment by thresholds
- Bridson Poisson-disk sampling for spawn points
- Simple navmesh bake: walkable by slope and altitude (water level)
- ECS entities with stable 64-bit IDs via FNV-1a over canonical payload
- Canonical JSON output (sorted keys, compact) for reproducible diffs

Python 3.10+; no third-party packages.
"""

from __future__ import annotations

import argparse
import json
import math
import time
from dataclasses import dataclass, asdict, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

# =========================
# Deterministic RNG & Hashes
# =========================

FNV64_OFFSET = 0xcbf29ce484222325
FNV64_PRIME  = 0x100000001b3

def fnv1a64(data: bytes, seed: int = FNV64_OFFSET) -> int:
    h = seed & 0xFFFFFFFFFFFFFFFF
    for b in data:
        h ^= b
        h = (h * FNV64_PRIME) & 0xFFFFFFFFFFFFFFFF
    return h

class LCG:
    """Simple deterministic PRNG (LCG) only for sampling; not crypto."""
    def __init__(self, seed: int) -> None:
        self.s = (seed ^ 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
    def _step(self) -> int:
        self.s = (6364136223846793005 * self.s + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
        return self.s
    def uniform(self) -> float:
        return ((self._step() >> 11) & ((1<<53)-1)) / float(1<<53)
    def randint(self, a: int, b: int) -> int:
        return a + int(self.uniform() * (b - a + 1))
    def choice(self, arr: Sequence[Any]) -> Any:
        return arr[self.randint(0, len(arr)-1)]

# =========================
# Config
# =========================

@dataclass(slots=True)
class BiomeThresholds:
    water_level: float = 0.22
    sand_level: float  = 0.28
    grass_level: float = 0.65
    rock_level: float  = 0.85

@dataclass(slots=True)
class ZoneConfig:
    size_x: int = 256          # tiles in X
    size_z: int = 256          # tiles in Z
    tile_size: float = 1.0     # world units per tile
    seed: int = 1337
    zone_id: str = "zone:minimal"
    max_players: int = 32
    biome: BiomeThresholds = field(default_factory=BiomeThresholds)
    poisson_radius: float = 6.0     # min distance for Poisson sampling (world units)
    poisson_k: int = 30             # Bridson k
    slope_max_deg: float = 42.0     # max slope to be walkable
    resources_per_km2: int = 350    # density target (normalized later)
    spawner_density: float = 0.15   # share of poisson points to allocate to NPC spawners

# =========================
# Utility: canonical JSON
# =========================

def cjson(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

# =========================
# Value Noise (2D), multi-octave
# =========================

def _hash2(x: int, y: int, seed: int) -> int:
    return fnv1a64(f"{x},{y},{seed}".encode("utf-8"))

def value_noise(x: float, z: float, seed: int) -> float:
    """Value noise (grid hashed), smoothstep interpolation, in [0,1]."""
    xi, zi = math.floor(x), math.floor(z)
    xf, zf = x - xi, z - zi
    def rnd(ix: int, iz: int) -> float:
        return ((_hash2(ix, iz, seed) >> 11) & ((1<<53)-1)) / float(1<<53)
    def smooth(t: float) -> float:
        return t*t*(3-2*t)
    r00 = rnd(xi, zi)
    r10 = rnd(xi+1, zi)
    r01 = rnd(xi, zi+1)
    r11 = rnd(xi+1, zi+1)
    sx, sz = smooth(xf), smooth(zf)
    ix0 = r00 + (r10 - r00) * sx
    ix1 = r01 + (r11 - r01) * sx
    v = ix0 + (ix1 - ix0) * sz
    return v

def fractal_noise(x: float, z: float, seed: int, octaves: int = 5, lacunarity: float = 2.0, gain: float = 0.5) -> float:
    amp = 1.0
    freq = 1.0
    sumv = 0.0
    norm = 0.0
    for o in range(octaves):
        sumv += amp * value_noise(x*freq, z*freq, seed + 1013*o)
        norm += amp
        amp *= gain
        freq *= lacunarity
    return sumv / max(1e-9, norm)

# =========================
# Poisson Disk Sampling (Bridson)
# =========================

def poisson_disc(width: float, height: float, radius: float, k: int, rng: LCG) -> List[Tuple[float,float]]:
    cell = radius / math.sqrt(2)
    grid_w = int(math.ceil(width / cell))
    grid_h = int(math.ceil(height / cell))
    grid: List[Optional[Tuple[float,float]]] = [None]*(grid_w*grid_h)
    def gi(px: float, pz: float) -> Tuple[int,int]:
        return int(px / cell), int(pz / cell)
    pts: List[Tuple[float,float]] = []
    active: List[Tuple[float,float]] = []

    # initial point
    p0 = (rng.uniform()*width, rng.uniform()*height)
    pts.append(p0); active.append(p0)
    gx, gz = gi(*p0)
    grid[gz*grid_w + gx] = p0

    while active:
        idx = rng.randint(0, len(active)-1)
        px, pz = active[idx]
        found = False
        for _ in range(k):
            ang = rng.uniform()*2*math.pi
            r = radius*(1 + rng.uniform())
            qx = px + r*math.cos(ang)
            qz = pz + r*math.sin(ang)
            if qx < 0 or qz < 0 or qx >= width or qz >= height:
                continue
            qgx, qgz = gi(qx, qz)
            ok = True
            for gz2 in range(max(0,qgz-2), min(grid_h, qgz+3)):
                for gx2 in range(max(0,qgx-2), min(grid_w, qgx+3)):
                    pt = grid[gz2*grid_w + gx2]
                    if pt:
                        dx = pt[0]-qx; dz = pt[1]-qz
                        if dx*dx + dz*dz < radius*radius:
                            ok = False; break
                if not ok: break
            if ok:
                grid[qgz*grid_w + qgx] = (qx,qz)
                pts.append((qx,qz))
                active.append((qx,qz))
                found = True
                break
        if not found:
            active.pop(idx)
    return pts

# =========================
# Navmesh bake (simple)
# =========================

def slope_deg(h00: float, h10: float, h01: float, h11: float, tile: float) -> float:
    # estimate gradient via central differences
    dx = ((h10 - h00) + (h11 - h01)) * 0.5
    dz = ((h01 - h00) + (h11 - h10)) * 0.5
    # slope = arctan(|grad| * scale); heights are [0,1], scale by tile
    grad = math.sqrt(dx*dx + dz*dz) / max(1e-6, tile)
    return math.degrees(math.atan(grad))

# =========================
# ECS helpers
# =========================

def eid_for(kind: str, payload: Mapping[str, Any]) -> int:
    b = f"{kind}:{cjson(payload)}".encode("utf-8")
    return fnv1a64(b)

def transform(x: float, y: float, z: float, yaw: float = 0.0, pitch: float = 0.0) -> Dict[str, Any]:
    return {"Transform": {"position": {"x": x, "y": y, "z": z}, "rotation": {"yaw": yaw, "pitch": pitch}}}

# =========================
# World generation
# =========================

@dataclass(slots=True)
class WorldOut:
    meta: Dict[str, Any]
    tiles: Dict[str, Any]
    entities: List[Dict[str, Any]]

def generate(cfg: ZoneConfig) -> WorldOut:
    rng = LCG(cfg.seed)
    W, H = cfg.size_x, cfg.size_z
    TS = cfg.tile_size

    # Height field (normalized)
    heights: List[float] = [0.0]*(W*H)
    # Use scale to get larger features
    scale = 0.045
    for z in range(H):
        for x in range(W):
            h = fractal_noise(x*scale, z*scale, cfg.seed, octaves=5, lacunarity=2.1, gain=0.53)
            heights[z*W + x] = h

    # Biomes
    bt = cfg.biome
    biomes: List[str] = [""]*(W*H)
    for z in range(H):
        for x in range(W):
            h = heights[z*W + x]
            if h < bt.water_level: b = "water"
            elif h < bt.sand_level: b = "sand"
            elif h < bt.grass_level: b = "grass"
            elif h < bt.rock_level: b = "rock"
            else: b = "snow"
            biomes[z*W + x] = b

    # Navmesh walkability by slope and water
    walkable: List[bool] = [False]*(W*H)
    for z in range(H-1):
        for x in range(W-1):
            h00 = heights[z*W + x]
            h10 = heights[z*W + (x+1)]
            h01 = heights[(z+1)*W + x]
            h11 = heights[(z+1)*W + (x+1)]
            sd = slope_deg(h00,h10,h01,h11, TS)
            ok = (sd <= cfg.slope_max_deg) and (h00 > bt.water_level and h10 > bt.water_level and h01 > bt.water_level and h11 > bt.water_level)
            walkable[z*W + x] = ok
    # last row/col fallback
    for x in range(W): walkable[(H-1)*W + x] = False
    for z in range(H): walkable[z*W + (W-1)] = False

    # Spawns via Poisson in world units, then snap to nearest walkable tile
    width_m  = W * TS
    height_m = H * TS
    pts = poisson_disc(width_m, height_m, cfg.poisson_radius, cfg.poisson_k, rng)

    # Assign subset to NPC spawners; remainder => resource nodes density-limited
    spawner_count = max(1, int(len(pts) * cfg.spawner_density))
    rng_idx = list(range(len(pts)))
    # Fisher–Yates with deterministic RNG
    for i in range(len(rng_idx)-1, 0, -1):
        j = rng.randint(0, i)
        rng_idx[i], rng_idx[j] = rng_idx[j], rng_idx[i]
    sp_indices = set(rng_idx[:spawner_count])

    entities: List[Dict[str, Any]] = []

    # Zone meta entity
    zone_payload = {
        "id": cfg.zone_id,
        "size": {"x": W, "z": H, "tile": TS},
        "seed": cfg.seed,
        "biomes": asdict(cfg.biome),
        "limits": {"players": cfg.max_players}
    }
    zone_eid = eid_for("ZoneMeta", zone_payload)
    entities.append({"id": zone_eid, "ZoneMeta": zone_payload})

    # Place spawners/resources
    resource_density = cfg.resources_per_km2 / 1_000_000.0  # per m^2
    area = width_m * height_m
    target_resources = max(1, int(area * resource_density))
    placed_resources = 0

    def snap_to_walkable(wx: float, wz: float) -> Optional[Tuple[float,float,float]]:
        tx = int(wx / TS); tz = int(wz / TS)
        if tx < 0 or tz < 0 or tx >= W-1 or tz >= H-1:
            return None
        if not walkable[tz*W + tx]:
            return None
        # world Y from height in meters: map [0,1] to some meters (e.g., 0..30m)
        y = heights[tz*W + tx] * 30.0
        xw = (tx + 0.5) * TS
        zw = (tz + 0.5) * TS
        return (xw, y, zw)

    # deterministic biome-based resource type table
    res_types = {
        "grass": ("berry_bush", "tree_oak", "stone_small"),
        "sand":  ("cactus", "driftwood", "stone_small"),
        "rock":  ("ore_iron", "stone_large"),
        "snow":  ("tree_pine", "ore_coal"),
    }

    for i, (wx, wz) in enumerate(pts):
        pos = snap_to_walkable(wx, wz)
        if not pos:
            continue
        xw, yw, zw = pos
        tile_index = int((zw/TS))*W + int((xw/TS))
        biome_here = biomes[min(tile_index, len(biomes)-1)]
        if i in sp_indices:
            payload = {
                "zone": cfg.zone_id,
                "type": "npc_spawner",
                "biome": biome_here,
                "radius": cfg.poisson_radius * 0.9,
                "cooldown_s": 30,
                "max_alive": 4
            }
            eid = eid_for("Spawner", {"pos":[round(xw,3), round(yw,3), round(zw,3)], **payload})
            ent = {"id": eid, **transform(xw, yw, zw), "Spawner": payload}
            entities.append(ent)
        else:
            if placed_resources >= target_resources:
                continue
            # pick resource type deterministically by hash
            types = res_types.get(biome_here, ("stone_small",))
            kind = types[_hash2(int(xw*1000), int(zw*1000), cfg.seed) % len(types)]
            payload = {
                "zone": cfg.zone_id,
                "type": "resource",
                "resource": kind,
                "respawn_s": 120
            }
            eid = eid_for("Resource", {"pos":[round(xw,3), round(yw,3), round(zw,3)], **payload})
            ent = {"id": eid, **transform(xw, yw, zw), "Resource": payload}
            entities.append(ent)
            placed_resources += 1

    # Tiles summary (compact)
    tiles = {
        "width": W, "height": H, "tile": TS,
        "heights_min": min(heights), "heights_max": max(heights),
        "biome_thresholds": asdict(cfg.biome),
        "water_level": cfg.biome.water_level,
        # For minimal example мы не выгружаем весь массив высот/тайлов, чтобы не раздувать JSON.
        # Детальная карта может формироваться по запросу других инструментов.
    }

    meta = {
        "schema": "engine-core.minimal-zone/1.0",
        "created_utc": _utc_iso(),
        "zone_id": cfg.zone_id,
        "rng_seed": cfg.seed,
        "engine_hint": "ecs-json",
        "counts": {"entities": len(entities), "spawners": sum(1 for e in entities if "Spawner" in e), "resources": sum(1 for e in entities if "Resource" in e)},
    }

    return WorldOut(meta=meta, tiles=tiles, entities=entities)

# =========================
# Helpers
# =========================

def _utc_iso() -> str:
    import datetime as _dt
    return _dt.datetime.utcfromtimestamp(time.time()).replace(microsecond=0).isoformat() + "Z"

def to_serializable(o: Any) -> Any:
    if isinstance(o, (WorldOut, ZoneConfig, BiomeThresholds)):
        return asdict(o)
    return o

# =========================
# CLI
# =========================

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Minimal deterministic zone seeder")
    p.add_argument("--seed", type=int, default=1337, help="Seed for deterministic generation")
    p.add_argument("--zone-id", type=str, default="zone:minimal", help="Zone identifier")
    p.add_argument("--size-x", type=int, default=256, help="Tiles X")
    p.add_argument("--size-z", type=int, default=256, help="Tiles Z")
    p.add_argument("--tile", type=float, default=1.0, help="World units per tile")
    p.add_argument("--players", type=int, default=32, help="Max players")
    p.add_argument("--poisson-radius", type=float, default=6.0, help="Min distance between points (world units)")
    p.add_argument("--resources", type=int, default=350, help="Target resource density per km^2")
    p.add_argument("--spawner-share", type=float, default=0.15, help="Share of points used for NPC spawners [0..1]")
    p.add_argument("-o", "--out", type=str, default="", help="Output path (JSON). If empty, print to stdout")
    p.add_argument("--pretty", action="store_true", help="Pretty-print JSON")
    return p.parse_args()

def main() -> int:
    a = parse_args()
    if a.size_x < 8 or a.size_z < 8:
        print("size must be >= 8", flush=True)
        return 1
    cfg = ZoneConfig(
        size_x=int(a.size_x),
        size_z=int(a.size_z),
        tile_size=float(a.tile),
        seed=int(a.seed),
        zone_id=str(a.zone_id),
        max_players=int(a.players),
    )
    cfg.poisson_radius = float(a.poisson_radius)
    cfg.resources_per_km2 = int(a.resources)
    cfg.spawner_density = max(0.0, min(1.0, float(a.spawner_share)))

    world = generate(cfg)
    payload = {"meta": world.meta, "tiles": world.tiles, "entities": world.entities}

    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            if a.pretty:
                json.dump(payload, f, ensure_ascii=False, indent=2, sort_keys=True)
            else:
                f.write(cjson(payload))
        return 0
    else:
        if a.pretty:
            print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
        else:
            print(cjson(payload))
        return 0

if __name__ == "__main__":
    raise SystemExit(main())
