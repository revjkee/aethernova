// frontend/src/pages/WorldEditor.tsx
import React, { Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Canvas, useLoader } from "@react-three/fiber";
import { OrbitControls, TransformControls, StatsGl } from "@react-three/drei";
import * as THREE from "three";
import { GLTFLoader } from "three/examples/jsm/loaders/GLTFLoader.js";

// shadcn/ui
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Switch } from "@/components/ui/switch";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";

// icons (актуальные имена из lucide-react; удалены неиспользуемые)
import {
  Box, Sphere, Move, RotateCw, FileUp, FileDown, Trash2, Copy, Square, SunMedium,
  Redo2, Undo2, Settings2, RefreshCcw, Rocket, ListTree, Camera, Wand2, Grid2x2, Download, Scale
} from "lucide-react";

// -----------------------------
// Types and constants
// -----------------------------
type Vec3 = [number, number, number];
type Euler3 = [number, number, number];

type PrimitiveKind = "box" | "sphere" | "plane";
type LightKind = "directional" | "point";
type NodeKind = "primitive" | "light" | "gltf";

type UUID = string;

interface BaseNode {
  id: UUID;
  name: string;
  kind: NodeKind;
  position: Vec3;
  rotation: Euler3; // radians
  scale: Vec3;
  visible: boolean;
  parentId?: UUID | null;
}

interface PrimitiveNode extends BaseNode {
  kind: "primitive";
  primitive: PrimitiveKind;
  color: string;
}

interface LightNode extends BaseNode {
  kind: "light";
  light: LightKind;
  intensity: number;
  color: string;
}

interface GLTFNode extends BaseNode {
  kind: "gltf";
  url: string; // objectURL или удаленный URL
}

type SceneNode = PrimitiveNode | LightNode | GLTFNode;

interface WorldState {
  nodes: SceneNode[];
}

const DEFAULT_WORLD: WorldState = { nodes: [] };

const LOCALSTORE_KEY = "world-editor.scene.v2";
const PREFS_KEY = "world-editor.prefs.v2";

const SNAP_VALUES = [0, 0.1, 0.25, 0.5, 1, 2, 5];
const ROT_SNAP_VALUES = [0, Math.PI / 16, Math.PI / 8, Math.PI / 4, Math.PI / 2];

// -----------------------------
// Utilities
// -----------------------------
const deepClone = <T,>(obj: T): T => {
  try {
    // @ts-ignore
    if (typeof structuredClone === "function") return structuredClone(obj);
  } catch {}
  return JSON.parse(JSON.stringify(obj));
};

const uuid = (): string =>
  (typeof crypto !== "undefined" && "randomUUID" in crypto
    ? crypto.randomUUID()
    : "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, c => {
        const r = (Math.random() * 16) | 0, v = c === "x" ? r : (r & 0x3) | 0x8;
        return v.toString(16);
      }));

const clampScale = (v: number) => Math.max(0.001, Math.min(1000, v));
const toFixed = (n: number, d = 3) => (Number.isFinite(n) ? Number(n.toFixed(d)) : 0);
const safeParse = (s: string, fallback = 0) => {
  const n = Number(s);
  return Number.isFinite(n) ? n : fallback;
};

const downloadBlob = (blob: Blob, filename: string) => {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
};

const fileOpen = async (accept: string): Promise<File | null> => {
  return new Promise((resolve) => {
    const inp = document.createElement("input");
    inp.type = "file";
    inp.accept = accept;
    inp.onchange = () => resolve(inp.files?.[0] ?? null);
    inp.click();
  });
};

// -----------------------------
// History (Undo/Redo)
// -----------------------------
function useHistory<T>(initial: T) {
  const [present, setPresent] = useState<T>(initial);
  const past = useRef<T[]>([]);
  const future = useRef<T[]>([]);

  const commit = useCallback((next: T) => {
    past.current.push(deepClone(present));
    future.current = [];
    setPresent(next);
  }, [present]);

  const undo = useCallback(() => {
    const prev = past.current.pop();
    if (prev) {
      future.current.push(deepClone(present));
      setPresent(prev);
    }
  }, [present]);

  const redo = useCallback(() => {
    const nxt = future.current.pop();
    if (nxt) {
      past.current.push(deepClone(present));
      setPresent(nxt);
    }
  }, [present]);

  const canUndo = past.current.length > 0;
  const canRedo = future.current.length > 0;

  const replace = useCallback((next: T) => setPresent(next), []);
  const reset = useCallback((next: T) => {
    past.current = [];
    future.current = [];
    setPresent(next);
  }, []);

  return { state: present, set: replace, commit, undo, redo, canUndo, canRedo, reset };
}

// -----------------------------
// Persistence (LocalStorage)
// -----------------------------
function loadWorld(): WorldState | null {
  try {
    const raw = localStorage.getItem(LOCALSTORE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as WorldState;
    if (!Array.isArray(parsed.nodes)) return null;
    return parsed;
  } catch {
    return null;
  }
}
function saveWorld(world: WorldState) {
  try {
    localStorage.setItem(LOCALSTORE_KEY, JSON.stringify(world));
  } catch {}
}

type Prefs = {
  orbitEnabled: boolean;
  transformMode: "translate" | "rotate" | "scale";
  snap: number;
  rotSnap: number;
  showStats: boolean;
  showGrid: boolean;
  showAxes: boolean;
};
const DEFAULT_PREFS: Prefs = {
  orbitEnabled: true,
  transformMode: "translate",
  snap: 0.5,
  rotSnap: 0,
  showStats: false,
  showGrid: true,
  showAxes: true,
};
function loadPrefs(): Prefs {
  try {
    const raw = localStorage.getItem(PREFS_KEY);
    return raw ? { ...DEFAULT_PREFS, ...(JSON.parse(raw) as Prefs) } : DEFAULT_PREFS;
  } catch {
    return DEFAULT_PREFS;
  }
}
function savePrefs(p: Prefs) {
  try {
    localStorage.setItem(PREFS_KEY, JSON.stringify(p));
  } catch {}
}

// -----------------------------
// Scene helpers
// -----------------------------
function defaultPrimitive(kind: PrimitiveKind): PrimitiveNode {
  return {
    id: uuid(),
    name: `Primitive-${kind}`,
    kind: "primitive",
    primitive: kind,
    color: "#cccccc",
    position: [0, kind === "sphere" ? 0.5 : kind === "box" ? 0.5 : 0, 0],
    rotation: [0, 0, 0],
    scale: [1, 1, 1],
    visible: true,
  };
}
function defaultLight(kind: LightKind): LightNode {
  return {
    id: uuid(),
    name: `Light-${kind}`,
    kind: "light",
    light: kind,
    intensity: kind === "point" ? 600 : 3,
    color: "#ffffff",
    position: [2, 4, 2],
    rotation: [0, 0, 0],
    scale: [1, 1, 1],
    visible: true,
  };
}

// -----------------------------
// 3D Renderable nodes
// -----------------------------
function PrimitiveMesh({ node, selected, onSelect }: { node: PrimitiveNode; selected: boolean; onSelect: () => void }) {
  const ref = useRef<THREE.Mesh>(null);
  useEffect(() => {
    if (ref.current) ref.current.visible = node.visible;
  }, [node.visible]);

  let geometry: React.ReactNode = null;
  if (node.primitive === "box") geometry = <boxGeometry args={[1, 1, 1]} />;
  if (node.primitive === "sphere") geometry = <sphereGeometry args={[0.5, 32, 32]} />;
  if (node.primitive === "plane") geometry = <planeGeometry args={[2, 2]} />;

  return (
    <mesh
      ref={ref}
      position={node.position}
      rotation={node.rotation as any}
      scale={node.scale}
      onClick={(e) => { e.stopPropagation(); onSelect(); }}
      castShadow
      receiveShadow
    >
      {geometry}
      <meshStandardMaterial color={node.color} />
      {selected && (
        <mesh>
          <boxGeometry args={[1.06, 1.06, 1.06]} />
          <meshBasicMaterial color="#4f46e5" wireframe transparent opacity={0.35} />
        </mesh>
      )}
    </mesh>
  );
}

function LightObject({ node, onSelect }: { node: LightNode; onSelect: () => void }) {
  const ref = useRef<THREE.Object3D>(null);
  useEffect(() => {
    if (ref.current) ref.current.visible = node.visible;
  }, [node.visible]);
  const color = useMemo(() => new THREE.Color(node.color), [node.color]);
  return (
    <group
      ref={ref}
      position={node.position}
      rotation={node.rotation as any}
      onClick={(e) => { e.stopPropagation(); onSelect(); }}
    >
      {node.light === "directional" ? (
        <directionalLight castShadow intensity={node.intensity} color={color} position={[0, 0, 0]} />
      ) : (
        <pointLight castShadow intensity={node.intensity} color={color} position={[0, 0, 0]} />
      )}
      <mesh>
        <sphereGeometry args={[0.08, 12, 12]} />
        <meshBasicMaterial color={node.color} />
      </mesh>
    </group>
  );
}

function GLTFObject({ node, onSelect }: { node: GLTFNode; onSelect: () => void }) {
  const gltf = useLoader(GLTFLoader, node.url);
  const ref = useRef<THREE.Object3D>(null);
  useEffect(() => {
    if (ref.current) ref.current.visible = node.visible;
  }, [node.visible]);
  return (
    <primitive
      ref={ref}
      object={gltf.scene}
      position={node.position}
      rotation={node.rotation as any}
      scale={node.scale}
      onClick={(e: any) => { e.stopPropagation(); onSelect(); }}
    />
  );
}

// -----------------------------
// Viewport with transform controls
// -----------------------------
function Viewport(props: {
  world: WorldState;
  selectedId: UUID | null;
  setSelectedId: (id: UUID | null) => void;
  onNodeChange: (id: UUID, patch: Partial<SceneNode>) => void;
  prefs: Prefs;
}) {
  const { world, selectedId, setSelectedId, onNodeChange, prefs } = props;
  const selectedNode = useMemo(() => world.nodes.find(n => n.id === selectedId) ?? null, [world, selectedId]);

  // Прокси-объект для TransformControls
  const proxyRef = useRef<THREE.Group>(null);
  useEffect(() => {
    if (!proxyRef.current || !selectedNode) return;
    proxyRef.current.position.set(...selectedNode.position);
    proxyRef.current.rotation.set(...(selectedNode.rotation as any));
    proxyRef.current.scale.set(...selectedNode.scale);
  }, [selectedNode?.position, selectedNode?.rotation, selectedNode?.scale, selectedNode?.id]);

  const onObjectChange = useCallback(() => {
    if (!proxyRef.current || !selectedNode) return;
    const p = proxyRef.current.position;
    const r = proxyRef.current.rotation;
    const s = proxyRef.current.scale;
    onNodeChange(selectedNode.id, {
      position: [p.x, p.y, p.z],
      rotation: [r.x, r.y, r.z],
      scale: [clampScale(s.x), clampScale(s.y), clampScale(s.z)],
    } as Partial<SceneNode>);
  }, [selectedNode, onNodeChange]);

  const Grid = () => {
    const grid = useMemo(() => new THREE.GridHelper(50, 50, 0x444444, 0x222222), []);
    const gRef = useRef<THREE.Object3D>(null);
    useEffect(() => {
      if (gRef.current) gRef.current.visible = prefs.showGrid;
    }, [prefs.showGrid]);
    return <primitive ref={gRef} object={grid} />;
  };
  const Axes = () => {
    const axes = useMemo(() => new THREE.AxesHelper(2), []);
    const aRef = useRef<THREE.Object3D>(null);
    useEffect(() => {
      if (aRef.current) aRef.current.visible = prefs.showAxes;
    }, [prefs.showAxes]);
    return <primitive ref={aRef} object={axes} />;
  };

  return (
    <Canvas
      shadows
      camera={{ position: [6, 5, 6], fov: 50 }}
      onPointerMissed={() => setSelectedId(null)}
      dpr={[1, 2]}
    >
      <color attach="background" args={["#0b0b0c"]} />
      <ambientLight intensity={0.5} />
      <directionalLight position={[8, 10, 5]} intensity={1.2} castShadow />

      {prefs.showGrid && <Grid />}
      {prefs.showAxes && <Axes />}

      {world.nodes.map((n) => {
        const selected = selectedId === n.id;
        const onSelect = () => setSelectedId(n.id);
        if (n.kind === "primitive") {
          return <PrimitiveMesh key={n.id} node={n} selected={selected} onSelect={onSelect} />;
        } else if (n.kind === "light") {
          return <LightObject key={n.id} node={n} onSelect={onSelect} />;
        } else {
          return <GLTFObject key={n.id} node={n} onSelect={onSelect} />;
        }
      })}

      {selectedNode && (
        <TransformControls
          mode={prefs.transformMode}
          // Универсальный обработчик (совместим с разными версиями drei):
          onChange={onObjectChange}
          // В некоторых d.ts нет этих пропсов — прокидываем через any
          {...({
            translationSnap: prefs.snap || undefined,
            rotationSnap: prefs.rotSnap || undefined,
            scaleSnap: prefs.snap || undefined,
          } as any)}
        >
          <group
            ref={proxyRef}
            position={selectedNode.position}
            rotation={selectedNode.rotation as any}
            scale={selectedNode.scale}
          />
        </TransformControls>
      )}

      <OrbitControls makeDefault enabled={prefs.orbitEnabled} />
      {prefs.showStats && <StatsGl />}
    </Canvas>
  );
}

// -----------------------------
// WorldEditor Page
// -----------------------------
export default function WorldEditor() {
  const loaded = loadWorld();
  const { state: world, commit, reset, undo, redo, canUndo, canRedo } = useHistory<WorldState>(loaded ?? DEFAULT_WORLD);
  const [selectedId, setSelectedId] = useState<UUID | null>(world.nodes[0]?.id ?? null);
  const [prefs, setPrefs] = useState<Prefs>(loadPrefs());
  const [banner, setBanner] = useState<string | null>(null);

  // Persist
  useEffect(() => { saveWorld(world); }, [world]);
  useEffect(() => { savePrefs(prefs); }, [prefs]);

  // Keyboard shortcuts
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const mod = e.ctrlKey || e.metaKey;
      if (mod && e.key.toLowerCase() === "z") {
        e.preventDefault();
        if (e.shiftKey) redo(); else undo();
      } else if ((mod && e.key.toLowerCase() === "y") || (mod && e.shiftKey && e.key.toLowerCase() === "z")) {
        e.preventDefault();
        redo();
      } else if (e.key === "Delete" || e.key === "Backspace") {
        if (selectedId) {
          e.preventDefault();
          onDeleteSelected();
        }
      } else if (mod && e.key.toLowerCase() === "s") {
        e.preventDefault();
        exportJSON();
      } else if (e.shiftKey && e.key.toLowerCase() === "c") {
        e.preventDefault();
        addPrimitive("box");
      } else if (e.shiftKey && e.key.toLowerCase() === "s") {
        e.preventDefault();
        addPrimitive("sphere");
      } else if (e.shiftKey && e.key.toLowerCase() === "p") {
        e.preventDefault();
        addPrimitive("plane");
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [selectedId, undo, redo]);

  // Actions
  const updateNode = useCallback((id: UUID, patch: Partial<SceneNode>) => {
    const next = deepClone(world);
    const idx = next.nodes.findIndex(n => n.id === id);
    if (idx >= 0) {
      next.nodes[idx] = { ...next.nodes[idx], ...patch } as SceneNode;
      commit(next);
    }
  }, [world, commit]);

  const addPrimitive = (kind: PrimitiveKind) => {
    const node = defaultPrimitive(kind);
    const next = deepClone(world);
    next.nodes.push(node);
    commit(next);
    setSelectedId(node.id);
  };

  const addLight = (kind: LightKind) => {
    const node = defaultLight(kind);
    const next = deepClone(world);
    next.nodes.push(node);
    commit(next);
    setSelectedId(node.id);
  };

  const addGLTFLocal = async () => {
    const file = await fileOpen(".gltf,.glb,model/gltf-binary,model/gltf+json");
    if (!file) return;
    const url = URL.createObjectURL(file);
    const node: GLTFNode = {
      id: uuid(),
      name: `GLTF-${file.name}`,
      kind: "gltf",
      url,
      position: [0, 0, 0],
      rotation: [0, 0, 0],
      scale: [1, 1, 1],
      visible: true,
    };
    const next = deepClone(world);
    next.nodes.push(node);
    commit(next);
    setSelectedId(node.id);
    setBanner("GLTF импортирован локально.");
    setTimeout(() => setBanner(null), 3000);
  };

  const duplicateSelected = () => {
    if (!selectedId) return;
    const node = world.nodes.find(n => n.id === selectedId);
    if (!node) return;
    const copy = deepClone(node);
    copy.id = uuid();
    copy.name = node.name + " Copy";
    copy.position = [node.position[0] + 0.2, node.position[1], node.position[2] + 0.2];
    const next = deepClone(world);
    next.nodes.push(copy);
    commit(next);
    setSelectedId(copy.id);
  };

  const onDeleteSelected = () => {
    if (!selectedId) return;
    const next = deepClone(world);
    const idx = next.nodes.findIndex(n => n.id === selectedId);
    if (idx >= 0) {
      next.nodes.splice(idx, 1);
      commit(next);
      setSelectedId(null);
    }
  };

  const newScene = () => {
    reset(DEFAULT_WORLD);
    setSelectedId(null);
  };

  const exportJSON = () => {
    const blob = new Blob([JSON.stringify(world, null, 2)], { type: "application/json" });
    downloadBlob(blob, "world.json");
  };

  const importJSON = async () => {
    const file = await fileOpen("application/json,.json");
    if (!file) return;
    const text = await file.text();
    try {
      const parsed = JSON.parse(text) as WorldState;
      if (!Array.isArray(parsed.nodes)) throw new Error("Некорректная схема");
      reset(parsed);
      setBanner("Сцена импортирована из JSON.");
      setTimeout(() => setBanner(null), 3000);
    } catch {
      setBanner("Ошибка импорта JSON.");
      setTimeout(() => setBanner(null), 3000);
    }
  };

  const exportGLTF = async () => {
    try {
      const { GLTFExporter } = await import("three/examples/jsm/exporters/GLTFExporter.js");
      const exporter = new GLTFExporter();
      const scene = new THREE.Scene();

      for (const n of world.nodes) {
        let obj: THREE.Object3D | null = null;
        if (n.kind === "primitive") {
          const mat = new THREE.MeshStandardMaterial({ color: new THREE.Color((n as PrimitiveNode).color) });
          if (n.primitive === "box") obj = new THREE.Mesh(new THREE.BoxGeometry(1, 1, 1), mat);
          if (n.primitive === "sphere") obj = new THREE.Mesh(new THREE.SphereGeometry(0.5, 32, 32), mat);
          if (n.primitive === "plane") obj = new THREE.Mesh(new THREE.PlaneGeometry(2, 2), mat);
        } else if (n.kind === "light") {
          if (n.light === "directional") obj = new THREE.DirectionalLight(new THREE.Color((n as LightNode).color), (n as LightNode).intensity);
          if (n.light === "point") obj = new THREE.PointLight(new THREE.Color((n as LightNode).color), (n as LightNode).intensity);
        } else if (n.kind === "gltf") {
          // Для краткости пропускаем инлайн GLTF-модели при экспорте.
          continue;
        }
        if (obj) {
          obj.position.set(...n.position);
          (obj.rotation as any).set(...(n.rotation as any));
          obj.scale.set(...n.scale);
          obj.visible = n.visible;
          scene.add(obj);
        }
      }

      exporter.parse(
        scene,
        (gltf: ArrayBuffer | object) => {
          const isBinary = gltf instanceof ArrayBuffer;
          const blob = isBinary
            ? new Blob([gltf], { type: "model/gltf-binary" })
            : new Blob([JSON.stringify(gltf, null, 2)], { type: "model/gltf+json" });
          downloadBlob(blob, `world.${isBinary ? "glb" : "gltf"}`);
        },
        (err) => {
          console.error(err);
          setBanner("Ошибка GLTF экспорта.");
          setTimeout(() => setBanner(null), 3000);
        },
        { binary: true }
      );
    } catch {
      setBanner("GLTF экспортер недоступен в сборке.");
      setTimeout(() => setBanner(null), 3000);
    }
  };

  const selected = world.nodes.find(n => n.id === selectedId) ?? null;

  return (
    <TooltipProvider delayDuration={150}>
      <div className="flex h-[calc(100vh-64px)] w-full overflow-hidden">
        {/* Left sidebar */}
        <aside className="w-[290px] border-r bg-background flex flex-col">
          <Card className="m-3">
            <CardHeader className="pb-2">
              <CardTitle className="flex items-center gap-2 text-base">
                <Wand2 className="h-4 w-4" /> Инструменты
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              <div className="grid grid-cols-2 gap-2">
                <Button variant="outline" onClick={() => addPrimitive("box")} className="gap-2" title="Shift+C">
                  <Box className="h-4 w-4" /> Куб
                </Button>
                <Button variant="outline" onClick={() => addPrimitive("sphere")} className="gap-2" title="Shift+S">
                  <Sphere className="h-4 w-4" /> Сфера
                </Button>
                <Button variant="outline" onClick={() => addPrimitive("plane")} className="gap-2" title="Shift+P">
                  <Square className="h-4 w-4" /> Плоскость
                </Button>
                <Button variant="outline" onClick={() => addLight("directional")} className="gap-2">
                  <SunMedium className="h-4 w-4" /> Направл.
                </Button>
                <Button variant="outline" onClick={() => addLight("point")} className="gap-2">
                  <SunMedium className="h-4 w-4" /> Точечный
                </Button>
              </div>

              <Separator className="my-2" />

              <div className="flex gap-2">
                <Button variant="default" onClick={exportJSON} className="gap-2">
                  <FileDown className="h-4 w-4" /> JSON
                </Button>
                <Button variant="outline" onClick={importJSON} className="gap-2">
                  <FileUp className="h-4 w-4" /> Импорт
                </Button>
              </div>
              <div className="flex gap-2">
                <Button variant="outline" onClick={addGLTFLocal} className="gap-2">
                  <FileUp className="h-4 w-4" /> GLTF
                </Button>
                <Button variant="outline" onClick={exportGLTF} className="gap-2">
                  <Download className="h-4 w-4" /> Экспорт GLB
                </Button>
              </div>

              <Separator className="my-2" />

              <div className="flex items-center justify-between">
                <span className="text-sm">Показывать сетку</span>
                <Switch checked={prefs.showGrid} onCheckedChange={(v) => setPrefs({ ...prefs, showGrid: v })} />
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm">Показывать оси</span>
                <Switch checked={prefs.showAxes} onCheckedChange={(v) => setPrefs({ ...prefs, showAxes: v })} />
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm">Orbit Controls</span>
                <Switch checked={prefs.orbitEnabled} onCheckedChange={(v) => setPrefs({ ...prefs, orbitEnabled: v })} />
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm">Stats</span>
                <Switch checked={prefs.showStats} onCheckedChange={(v) => setPrefs({ ...prefs, showStats: v })} />
              </div>
            </CardContent>
          </Card>

          <Card className="m-3 flex-1 overflow-hidden">
            <CardHeader className="pb-2">
              <CardTitle className="flex items-center gap-2 text-base">
                <ListTree className="h-4 w-4" /> Сцена
              </CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              <ScrollArea className="h-full">
                <div className="p-2">
                  {world.nodes.length === 0 && <div className="text-xs text-muted-foreground">Пустая сцена</div>}
                  {world.nodes.map(n => (
                    <div
                      key={n.id}
                      className={`flex items-center justify-between rounded px-2 py-1 mb-1 border ${selectedId === n.id ? "border-primary bg-primary/10" : "border-transparent hover:bg-muted/50"}`}
                      onClick={() => setSelectedId(n.id)}
                    >
                      <div className="flex items-center gap-2">
                        {n.kind === "primitive" ? <Grid2x2 className="h-3.5 w-3.5" /> : n.kind === "light" ? <SunMedium className="h-3.5 w-3.5" /> : <Rocket className="h-3.5 w-3.5" />}
                        <span className="text-xs">{n.name}</span>
                      </div>
                      <div className="flex items-center gap-1">
                        <Switch
                          checked={n.visible}
                          onCheckedChange={(v) => updateNode(n.id, { visible: v })}
                        />
                        <Button size="icon" variant="ghost" onClick={(e) => { e.stopPropagation(); setSelectedId(n.id); duplicateSelected(); }}>
                          <Copy className="h-3.5 w-3.5" />
                        </Button>
                        <Button size="icon" variant="ghost" onClick={(e) => { e.stopPropagation(); setSelectedId(n.id); onDeleteSelected(); }}>
                          <Trash2 className="h-3.5 w-3.5" />
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        </aside>

        {/* Center: Viewport */}
        <main className="flex-1 relative bg-black">
          <div className="absolute inset-0">
            <Suspense fallback={<div className="w-full h-full flex items-center justify-center text-muted-foreground">Загрузка сцены...</div>}>
              <Viewport
                world={world}
                selectedId={selectedId}
                setSelectedId={setSelectedId}
                onNodeChange={updateNode}
                prefs={prefs}
              />
            </Suspense>
          </div>

          {/* Top toolbar */}
          <div className="absolute top-2 left-2 right-2 pointer-events-none">
            <div className="pointer-events-auto inline-flex gap-2 bg-background/80 backdrop-blur rounded-md border p-2">
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button variant="outline" onClick={newScene} className="gap-2">
                    <RefreshCcw className="h-4 w-4" /> Новая сцена
                  </Button>
                </TooltipTrigger>
                <TooltipContent>Очистить сцену</TooltipContent>
              </Tooltip>

              <Separator orientation="vertical" />

              <Tooltip>
                <TooltipTrigger asChild>
                  <Button variant="outline" disabled={!canUndo} onClick={undo} className="gap-1">
                    <Undo2 className="h-4 w-4" /> Undo
                  </Button>
                </TooltipTrigger>
                <TooltipContent>Ctrl/Cmd+Z</TooltipContent>
              </Tooltip>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button variant="outline" disabled={!canRedo} onClick={redo} className="gap-1">
                    <Redo2 className="h-4 w-4" /> Redo
                  </Button>
                </TooltipTrigger>
                <TooltipContent>Ctrl/Cmd+Y или Ctrl/Cmd+Shift+Z</TooltipContent>
              </Tooltip>

              <Separator orientation="vertical" />

              <div className="flex items-center gap-1">
                <Button
                  variant={prefs.transformMode === "translate" ? "default" : "outline"}
                  onClick={() => setPrefs({ ...prefs, transformMode: "translate" })}
                  className="gap-1"
                >
                  <Move className="h-4 w-4" /> Move
                </Button>
                <Button
                  variant={prefs.transformMode === "rotate" ? "default" : "outline"}
                  onClick={() => setPrefs({ ...prefs, transformMode: "rotate" })}
                  className="gap-1"
                >
                  <RotateCw className="h-4 w-4" /> Rotate
                </Button>
                <Button
                  variant={prefs.transformMode === "scale" ? "default" : "outline"}
                  onClick={() => setPrefs({ ...prefs, transformMode: "scale" })}
                  className="gap-1"
                >
                  <Scale className="h-4 w-4" /> Scale
                </Button>
              </div>

              <Separator orientation="vertical" />

              <div className="flex items-center gap-1">
                <Label className="text-xs px-2">Snap</Label>
                <Select
                  value={String(prefs.snap)}
                  onValueChange={(v) => setPrefs({ ...prefs, snap: Number(v) })}
                >
                  <SelectTrigger className="w-[88px] h-8">
                    <SelectValue placeholder="snap" />
                  </SelectTrigger>
                  <SelectContent>
                    {SNAP_VALUES.map(s => <SelectItem key={s} value={String(s)}>{s}</SelectItem>)}
                  </SelectContent>
                </Select>

                <Label className="text-xs px-2">Rot</Label>
                <Select
                  value={String(prefs.rotSnap)}
                  onValueChange={(v) => setPrefs({ ...prefs, rotSnap: Number(v) })}
                >
                  <SelectTrigger className="w-[110px] h-8">
                    <SelectValue placeholder="rot" />
                  </SelectTrigger>
                  <SelectContent>
                    {ROT_SNAP_VALUES.map(s => <SelectItem key={s} value={String(s)}>{toFixed(s)}</SelectItem>)}
                  </SelectContent>
                </Select>
              </div>
            </div>
          </div>

          {/* Banner */}
          {banner && (
            <div className="absolute bottom-3 left-1/2 -translate-x-1/2 bg-background/90 border rounded-md px-3 py-2 text-sm">
              {banner}
            </div>
          )}
        </main>

        {/* Right sidebar */}
        <aside className="w-[340px] border-l bg-background">
          <Card className="m-3">
            <CardHeader className="pb-2">
              <CardTitle className="flex items-center gap-2 text-base">
                <Settings2 className="h-4 w-4" /> Свойства
              </CardTitle>
            </CardHeader>
            <CardContent>
              {!selected ? (
                <div className="text-sm text-muted-foreground">Объект не выбран</div>
              ) : (
                <Tabs defaultValue="transform">
                  <TabsList className="grid grid-cols-3">
                    <TabsTrigger value="transform">Трансформ</TabsTrigger>
                    <TabsTrigger value="material">Материал/Свет</TabsTrigger>
                    <TabsTrigger value="meta">Мета</TabsTrigger>
                  </TabsList>

                  <TabsContent value="transform" className="space-y-3 pt-2">
                    <XYZInputs
                      label="Позиция"
                      value={selected.position}
                      onChange={(v) => updateNode(selected.id, { position: v })}
                    />
                    <XYZInputs
                      label="Поворот (рад)"
                      value={selected.rotation}
                      onChange={(v) => updateNode(selected.id, { rotation: v })}
                    />
                    <XYZInputs
                      label="Масштаб"
                      value={selected.scale}
                      onChange={(v) => updateNode(selected.id, { scale: v.map(clampScale) as Vec3 })}
                    />
                    <div className="flex items-center justify-between pt-1">
                      <span className="text-sm">Видимость</span>
                      <Switch checked={selected.visible} onCheckedChange={(v) => updateNode(selected.id, { visible: v })} />
                    </div>
                  </TabsContent>

                  <TabsContent value="material" className="space-y-3 pt-2">
                    {selected.kind === "primitive" && (
                      <>
                        <Label className="text-xs">Цвет</Label>
                        <Input
                          type="color"
                          value={(selected as PrimitiveNode).color}
                          onChange={(e) => updateNode(selected.id, { color: e.target.value } as any)}
                        />
                      </>
                    )}
                    {selected.kind === "light" && (
                      <>
                        <Label className="text-xs">Интенсивность</Label>
                        <Input
                          type="number"
                          step="0.1"
                          value={(selected as LightNode).intensity}
                          onChange={(e) => updateNode(selected.id, { intensity: safeParse(e.target.value, 1) } as any)}
                        />
                        <Label className="text-xs mt-2">Цвет</Label>
                        <Input
                          type="color"
                          value={(selected as LightNode).color}
                          onChange={(e) => updateNode(selected.id, { color: e.target.value } as any)}
                        />
                      </>
                    )}
                    {selected.kind === "gltf" && (
                      <div className="text-xs text-muted-foreground">
                        GLTF объект. Редактирование материалов не реализовано в этом файле.
                      </div>
                    )}
                  </TabsContent>

                  <TabsContent value="meta" className="space-y-3 pt-2">
                    <Label className="text-xs">Имя</Label>
                    <Input
                      value={selected.name}
                      onChange={(e) => updateNode(selected.id, { name: e.target.value })}
                    />
                    <div className="text-xs text-muted-foreground">
                      ID: {selected.id}
                    </div>
                    <div className="flex gap-2">
                      <Button variant="outline" className="gap-2" onClick={duplicateSelected}>
                        <Copy className="h-4 w-4" /> Дублировать
                      </Button>
                      <Button variant="destructive" className="gap-2" onClick={onDeleteSelected}>
                        <Trash2 className="h-4 w-4" /> Удалить
                      </Button>
                    </div>
                  </TabsContent>
                </Tabs>
              )}
            </CardContent>
          </Card>

          <Card className="m-3">
            <CardHeader className="pb-2">
              <CardTitle className="flex items-center gap-2 text-base">
                <Camera className="h-4 w-4" /> Подсказки
              </CardTitle>
            </CardHeader>
            <CardContent className="text-xs space-y-1 text-muted-foreground">
              <div>Ctrl/Cmd+Z — Undo, Ctrl/Cmd+Y — Redo, Delete — удалить</div>
              <div>Shift+C/S/P — добавить Куб/Сферу/Плоскость</div>
              <div>Верхняя панель — режим трансформации и шаг привязки</div>
              <div>Импорт GLTF использует objectURL (локально)</div>
              <div>Экспорт JSON сохраняет всю сцену</div>
            </CardContent>
          </Card>
        </aside>
      </div>
    </TooltipProvider>
  );
}

// -----------------------------
// UI helpers
// -----------------------------
function XYZInputs({ label, value, onChange }: { label: string; value: [number, number, number]; onChange: (v: [number, number, number]) => void }) {
  const [x, y, z] = value;
  return (
    <div className="space-y-1">
      <Label className="text-xs">{label}</Label>
      <div className="grid grid-cols-3 gap-2">
        <Input
          inputMode="numeric"
          value={toFixed(x)}
          onChange={(e) => onChange([safeParse(e.target.value, x), y, z])}
        />
        <Input
          inputMode="numeric"
          value={toFixed(y)}
          onChange={(e) => onChange([x, safeParse(e.target.value, y), z])}
        />
        <Input
          inputMode="numeric"
          value={toFixed(z)}
          onChange={(e) => onChange([x, y, safeParse(e.target.value, z)])}
        />
      </div>
    </div>
  );
}
