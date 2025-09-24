/* engine-core/engine/clients/web-threejs-minimal/main.js
 * Industrial-grade minimal Three.js client with WS sync:
 * - Robust WebSocket (reconnect with backoff, ping/pong, RTT)
 * - JSON and binary messages (ArrayBuffer) support
 * - Points and Capsules via InstancedMesh (GPU instancing)
 * - OrbitControls (inline, no external import)
 * - Perf overlay (FPS, frame time, entities, RTT)
 * - HiDPI-aware rendering, resize handling
 * - Safe memory (free-list for instances), partial updates
 * - Scene slicing (near/far & max entities)
 */

/* ====== CONFIG ====== */
const CFG = {
  WS_URL: (location.protocol === "https:" ? "wss://" : "ws://") + location.host + "/ws",
  MAX_POINTS: 50000,
  MAX_CAPSULES: 10000,
  DPR_MAX: 2.0,
  PING_INTERVAL_MS: 5000,
  BACKOFF: { base: 500, max: 10000 },
  CAMERA: { fov: 60, near: 0.1, far: 5000, start: [10, 10, 10] },
  SCENE: { bg: 0x0b0f14, fog: { color: 0x0b0f14, density: 0.0008 } },
  POINTS: { radius: 0.05, color: 0x66ccff, opacity: 0.95 },
  CAPSULES: { radius: 0.08, color: 0xffaa55, opacity: 0.95 }
};

/* ====== THREE CORE (from module build) ======
 * This file assumes you include three.module.js and controls in your bundler environment,
 * but to keep a single file, we import from global THREE if available (UMD build).
 */
const THREE = window.THREE;
if (!THREE) {
  throw new Error("THREE.js is required. Load three.min.js before main.js");
}

/* ====== INLINE ORBIT CONTROLS (trimmed minimal) ====== */
class OrbitControls {
  constructor(object, domElement) {
    this.object = object;
    this.domElement = domElement;
    this.enabled = true;
    this.target = new THREE.Vector3();
    this.minDistance = 1;
    this.maxDistance = 2000;
    this.minPolarAngle = 0;
    this.maxPolarAngle = Math.PI;
    this.rotateSpeed = 0.9;
    this.zoomSpeed = 1.0;
    this.panSpeed = 0.8;

    let state = "none";
    const pointer = new THREE.Vector2();
    const rotateStart = new THREE.Vector2();
    const rotateEnd = new THREE.Vector2();
    const panStart = new THREE.Vector2();
    const panEnd = new THREE.Vector2();
    const scope = this;
    const spherical = new THREE.Spherical().setFromVector3(
      object.position.clone().sub(scope.target)
    );

    function getCanvasRect() { return scope.domElement.getBoundingClientRect(); }

    function onPointerDown(event) {
      if (!scope.enabled) return;
      scope.domElement.setPointerCapture(event.pointerId);
      if (event.button === 0) {
        state = "rotate";
        rotateStart.set(event.clientX, event.clientY);
      } else if (event.button === 1 || event.button === 2) {
        state = "pan";
        panStart.set(event.clientX, event.clientY);
      }
    }

    function onPointerMove(event) {
      if (!scope.enabled) return;
      if (state === "rotate") {
        rotateEnd.set(event.clientX, event.clientY);
        const dx = (rotateEnd.x - rotateStart.x) * scope.rotateSpeed * 0.005;
        const dy = (rotateEnd.y - rotateStart.y) * scope.rotateSpeed * 0.005;
        spherical.theta -= dx;
        spherical.phi -= dy;
        spherical.phi = Math.max(scope.minPolarAngle, Math.min(scope.maxPolarAngle, spherical.phi));
        rotateStart.copy(rotateEnd);
        updateCamera();
      } else if (state === "pan") {
        panEnd.set(event.clientX, event.clientY);
        const rect = getCanvasRect();
        const dx = (panEnd.x - panStart.x) / rect.height;
        const dy = (panEnd.y - panStart.y) / rect.height;
        const pan = new THREE.Vector3();
        const te = scope.object.matrix.elements;
        // camera local axes
        const x = new THREE.Vector3(te[0], te[1], te[2]).multiplyScalar(-dx * scope.panSpeed * spherical.radius);
        const y = new THREE.Vector3(te[4], te[5], te[6]).multiplyScalar(dy * scope.panSpeed * spherical.radius);
        pan.copy(x).add(y);
        scope.object.position.add(pan);
        scope.target.add(pan);
        panStart.copy(panEnd);
      }
    }

    function onPointerUp(event) {
      scope.domElement.releasePointerCapture(event.pointerId);
      state = "none";
    }

    function onWheel(event) {
      if (!scope.enabled) return;
      const delta = Math.sign(event.deltaY) * scope.zoomSpeed;
      spherical.radius *= (1 + delta * 0.1);
      spherical.radius = Math.max(scope.minDistance, Math.min(scope.maxDistance, spherical.radius));
      updateCamera();
    }

    function updateCamera() {
      const offset = new THREE.Vector3().setFromSpherical(spherical);
      scope.object.position.copy(scope.target).add(offset);
      scope.object.lookAt(scope.target);
    }

    this.update = updateCamera;
    this.dispose = () => {
      scope.domElement.removeEventListener("pointerdown", onPointerDown);
      scope.domElement.removeEventListener("pointermove", onPointerMove);
      scope.domElement.removeEventListener("pointerup", onPointerUp);
      scope.domElement.removeEventListener("wheel", onWheel);
    };

    this.domElement.addEventListener("pointerdown", onPointerDown);
    this.domElement.addEventListener("pointermove", onPointerMove);
    this.domElement.addEventListener("pointerup", onPointerUp);
    this.domElement.addEventListener("wheel", onWheel, { passive: true });

    updateCamera();
  }
}

/* ====== PERF OVERLAY ====== */
class PerfOverlay {
  constructor() {
    this.root = document.createElement("div");
    Object.assign(this.root.style, {
      position: "fixed", top: "8px", left: "8px", padding: "6px 8px",
      background: "rgba(0,0,0,0.55)", color: "#cbd5e1", font: "12px/1.3 monospace",
      zIndex: 10000, borderRadius: "6px", pointerEvents: "none"
    });
    document.body.appendChild(this.root);
    this.last = performance.now();
    this.fps = 0; this.frames = 0;
    this.rtt = "n/a";
    this.entities = { points: 0, capsules: 0 };
  }
  setRTT(ms) { this.rtt = ms.toFixed(1) + " ms"; }
  setEntities(p, c) { this.entities.points = p; this.entities.capsules = c; }
  frame() {
    this.frames++;
    const now = performance.now();
    if (now - this.last >= 500) {
      this.fps = (this.frames * 1000) / (now - this.last);
      this.frames = 0; this.last = now;
      this.render();
    }
  }
  render() {
    this.root.textContent =
      `FPS: ${this.fps.toFixed(1)} | RTT: ${this.rtt} | Pts: ${this.entities.points} | Caps: ${this.entities.capsules}`;
  }
}

/* ====== RECONNECTING WS ====== */
class ReWS {
  constructor(url, { base = 500, max = 10000 } = {}) {
    this.url = url; this.base = base; this.max = max;
    this.ws = null; this.timer = null; this.handlers = {};
    this.pingTimer = null; this.pingOutstanding = false; this.lastPing = 0;
    this.onopen = null; this.onclose = null; this.onmessage = null;
    this.onbinary = null;
    this.start();
  }
  start() {
    const ws = new WebSocket(this.url);
    ws.binaryType = "arraybuffer";
    ws.onopen = () => {
      this.ws = ws; this._clearTimer();
      if (this.onopen) this.onopen();
      this._schedulePing();
    };
    ws.onclose = () => {
      this._clearPing();
      this._scheduleReconnect();
      if (this.onclose) this.onclose();
    };
    ws.onerror = () => { /* swallow, close will fire */ };
    ws.onmessage = (ev) => {
      if (ev.data instanceof ArrayBuffer) {
        if (this.onbinary) this.onbinary(ev.data);
      } else if (typeof ev.data === "string") {
        if (this.onmessage) this.onmessage(ev.data);
      }
    };
  }
  send(objOrStr) {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return;
    const payload = typeof objOrStr === "string" ? objOrStr : JSON.stringify(objOrStr);
    this.ws.send(payload);
  }
  sendBinary(buffer) {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return;
    this.ws.send(buffer);
  }
  _scheduleReconnect() {
    this._clearTimer();
    const tries = (this._tries || 0) + 1;
    this._tries = tries;
    const delay = Math.min(this.max, this.base * Math.pow(2, Math.min(tries, 6))) + Math.random() * 250;
    this.timer = setTimeout(() => this.start(), delay);
  }
  _clearTimer() { if (this.timer) { clearTimeout(this.timer); this.timer = null; } this._tries = 0; }
  _schedulePing() {
    this._clearPing();
    this.pingTimer = setInterval(() => {
      if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return;
      if (this.pingOutstanding) return; // wait previous
      this.pingOutstanding = true;
      this.lastPing = performance.now();
      this.send({ t: "ping", ts: Date.now() });
    }, CFG.PING_INTERVAL_MS);
  }
  _clearPing() { if (this.pingTimer) { clearInterval(this.pingTimer); this.pingTimer = null; } this.pingOutstanding = false; }
}

/* ====== GEOMETRY LAYERS ====== */
class FreeList {
  constructor(capacity) { this.stack = []; for (let i = capacity - 1; i >= 0; i--) this.stack.push(i); }
  alloc() { return this.stack.length ? this.stack.pop() : -1; }
  free(i) { if (i >= 0) this.stack.push(i); }
  size() { return this.stack.length; }
}

class PointsLayer {
  constructor(scene, capacity, { radius, color, opacity }) {
    this.capacity = capacity;
    this.map = new Map(); // id -> index
    this.free = new FreeList(capacity);

    const geom = new THREE.SphereGeometry(radius, 8, 8);
    const mat = new THREE.MeshStandardMaterial({
      color, opacity, transparent: opacity < 1.0, depthWrite: opacity >= 1.0
    });
    this.mesh = new THREE.InstancedMesh(geom, mat, capacity);
    this.mesh.instanceMatrix.setUsage(THREE.DynamicDrawUsage);
    this.mesh.instanceColor = new THREE.InstancedBufferAttribute(new Float32Array(capacity * 3), 3);
    this.mesh.instanceColor.setUsage(THREE.DynamicDrawUsage);

    scene.add(this.mesh);
    this.tmpObj = new THREE.Object3D();
    this.tmpColor = new THREE.Color(color);
    this.count = 0;
  }

  upsert(item) {
    // item: { id, x,y,z, color?[hex], opacity? }
    let idx = this.map.get(item.id);
    if (idx === undefined) {
      idx = this.free.alloc();
      if (idx < 0) return false;
      this.map.set(item.id, idx);
      this.count++;
    }
    this.tmpObj.position.set(item.x || 0, item.y || 0, item.z || 0);
    this.tmpObj.rotation.set(0, 0, 0);
    this.tmpObj.scale.set(1, 1, 1);
    this.tmpObj.updateMatrix();
    this.mesh.setMatrixAt(idx, this.tmpObj.matrix);
    const c = item.color !== undefined ? new THREE.Color(item.color) : this.tmpColor;
    this.mesh.instanceColor.setXYZ(idx, c.r, c.g, c.b);
    this.mesh.instanceMatrix.needsUpdate = true;
    this.mesh.instanceColor.needsUpdate = true;
    return true;
  }

  remove(id) {
    const idx = this.map.get(id);
    if (idx === undefined) return;
    // compact remove: move last used instance into freed slot
    const last = this.count - 1;
    if (idx !== last) {
      this.mesh.getMatrixAt(last, this.mesh.instanceMatrix.array instanceof Float32Array ? new THREE.Matrix4().fromArray(this.mesh.instanceMatrix.array, last * 16) : new THREE.Matrix4());
      const mat = new THREE.Matrix4();
      this.mesh.getMatrixAt(last, mat);
      this.mesh.setMatrixAt(idx, mat);
      const cr = this.mesh.instanceColor;
      cr.setXYZ(idx, cr.getX(last), cr.getY(last), cr.getZ(last));
      // find id of 'last' to update map
      for (const [k, v] of this.map.entries()) { if (v === last) { this.map.set(k, idx); break; } }
    }
    this.map.delete(id);
    this.free.free(last);
    this.count--;
    this.mesh.instanceMatrix.needsUpdate = true;
    this.mesh.instanceColor.needsUpdate = true;
  }

  stats() { return this.map.size; }
}

class CapsulesLayer {
  constructor(scene, capacity, { radius, color, opacity }) {
    this.capacity = capacity;
    this.map = new Map(); // id -> index
    this.free = new FreeList(capacity);

    const geom = new THREE.CapsuleGeometry(radius, 1.0, 6, 8); // unit length along Y
    const mat = new THREE.MeshStandardMaterial({
      color, opacity, transparent: opacity < 1.0, depthWrite: opacity >= 1.0
    });
    this.mesh = new THREE.InstancedMesh(geom, mat, capacity);
    this.mesh.instanceMatrix.setUsage(THREE.DynamicDrawUsage);
    this.mesh.instanceColor = new THREE.InstancedBufferAttribute(new Float32Array(capacity * 3), 3);
    this.mesh.instanceColor.setUsage(THREE.DynamicDrawUsage);

    scene.add(this.mesh);
    this.tmpObj = new THREE.Object3D();
    this.tmpQuat = new THREE.Quaternion();
    this.tmpUp = new THREE.Vector3(0, 1, 0);
    this.tmpDir = new THREE.Vector3();
    this.tmpColor = new THREE.Color(color);
    this.count = 0;
  }

  upsert(item) {
    // item: { id, ax,ay,az, bx,by,bz, color?[hex] }
    let idx = this.map.get(item.id);
    if (idx === undefined) {
      idx = this.free.alloc();
      if (idx < 0) return false;
      this.map.set(item.id, idx);
      this.count++;
    }
    const a = new THREE.Vector3(item.ax, item.ay, item.az);
    const b = new THREE.Vector3(item.bx, item.by, item.bz);
    const mid = new THREE.Vector3().addVectors(a, b).multiplyScalar(0.5);
    const dir = this.tmpDir.subVectors(b, a);
    const len = Math.max(1e-6, dir.length());
    dir.normalize();

    this.tmpQuat.setFromUnitVectors(this.tmpUp, dir);
    this.tmpObj.position.copy(mid);
    this.tmpObj.quaternion.copy(this.tmpQuat);
    // Scale Y to length; geometry has cylinder length 1 (end caps add radius) — we scale uniformly on Y
    this.tmpObj.scale.set(1, len, 1);
    this.tmpObj.updateMatrix();

    this.mesh.setMatrixAt(idx, this.tmpObj.matrix);
    const c = item.color !== undefined ? new THREE.Color(item.color) : this.tmpColor;
    this.mesh.instanceColor.setXYZ(idx, c.r, c.g, c.b);
    this.mesh.instanceMatrix.needsUpdate = true;
    this.mesh.instanceColor.needsUpdate = true;
    return true;
  }

  remove(id) {
    const idx = this.map.get(id);
    if (idx === undefined) return;
    const last = this.count - 1;
    if (idx !== last) {
      const mat = new THREE.Matrix4();
      this.mesh.getMatrixAt(last, mat);
      this.mesh.setMatrixAt(idx, mat);
      const cr = this.mesh.instanceColor;
      cr.setXYZ(idx, cr.getX(last), cr.getY(last), cr.getZ(last));
      for (const [k, v] of this.map.entries()) { if (v === last) { this.map.set(k, idx); break; } }
    }
    this.map.delete(id);
    this.free.free(last);
    this.count--;
    this.mesh.instanceMatrix.needsUpdate = true;
    this.mesh.instanceColor.needsUpdate = true;
  }

  stats() { return this.map.size; }
}

/* ====== APP ====== */
class App {
  constructor() {
    this.overlay = new PerfOverlay();

    this.scene = new THREE.Scene();
    this.scene.background = new THREE.Color(CFG.SCENE.bg);
    this.scene.fog = new THREE.FogExp2(CFG.SCENE.fog.color, CFG.SCENE.fog.density);

    this.camera = new THREE.PerspectiveCamera(
      CFG.CAMERA.fov, window.innerWidth / window.innerHeight, CFG.CAMERA.near, CFG.CAMERA.far
    );
    this.camera.position.set(...CFG.CAMERA.start);

    this.renderer = new THREE.WebGLRenderer({ antialias: true, powerPreference: "high-performance" });
    this.renderer.outputColorSpace = THREE.SRGBColorSpace || THREE.sRGBEncoding;
    this.renderer.toneMapping = THREE.ACESFilmicToneMapping ?? THREE.LinearToneMapping;
    document.body.style.margin = "0";
    document.body.appendChild(this.renderer.domElement);
    this._resize();

    this.controls = new OrbitControls(this.camera, this.renderer.domElement);

    // lights
    const hemi = new THREE.HemisphereLight(0xffffff, 0x202030, 0.8);
    const dir = new THREE.DirectionalLight(0xffffff, 0.8);
    dir.position.set(5, 10, 7);
    this.scene.add(hemi, dir);

    // grid helper
    const grid = new THREE.GridHelper(100, 100, 0x334155, 0x1f2937);
    grid.material.opacity = 0.25; grid.material.transparent = true;
    this.scene.add(grid);

    // layers
    this.points = new PointsLayer(this.scene, CFG.MAX_POINTS, CFG.POINTS);
    this.capsules = new CapsulesLayer(this.scene, CFG.MAX_CAPSULES, CFG.CAPSULES);

    // network
    this.ws = new ReWS(CFG.WS_URL, CFG.BACKOFF);
    this.ws.onopen = () => this.ws.send({ t: "hello", caps: ["points", "capsules"], dpr: window.devicePixelRatio });
    this.ws.onmessage = (txt) => this._handleJSON(txt);
    this.ws.onbinary = (buf) => this._handleBinary(buf);
    this.ws.onclose = () => { /* overlay keeps last RTT */ };

    window.addEventListener("resize", () => this._resize());
    this._animate();
  }

  _resize() {
    const dpr = Math.min(CFG.DPR_MAX, window.devicePixelRatio || 1);
    this.renderer.setPixelRatio(dpr);
    this.renderer.setSize(window.innerWidth, window.innerHeight, false);
    this.camera.aspect = window.innerWidth / window.innerHeight;
    this.camera.updateProjectionMatrix();
  }

  _animate() {
    requestAnimationFrame(() => this._animate());
    this.controls.update();
    this.renderer.render(this.scene, this.camera);
    this.overlay.setEntities(this.points.stats(), this.capsules.stats());
    this.overlay.frame();
  }

  /* ====== MESSAGE HANDLERS ====== */
  _handleJSON(txt) {
    let msg;
    try { msg = JSON.parse(txt); } catch { return; }
    const t = msg.t;
    if (t === "pong") {
      if (this.ws.pingOutstanding) {
        const rtt = performance.now() - this.ws.lastPing;
        this.overlay.setRTT(rtt);
        this.ws.pingOutstanding = false;
      }
      return;
    }
    if (t === "clear") {
      this._clear();
      return;
    }
    if (t === "upsert_points") {
      // msg.items: [{id, x,y,z, color?}]
      for (const it of msg.items) this.points.upsert(it);
      return;
    }
    if (t === "remove_points") {
      for (const id of msg.ids) this.points.remove(id);
      return;
    }
    if (t === "upsert_capsules") {
      // msg.items: [{id, ax,ay,az, bx,by,bz, color?}]
      for (const it of msg.items) this.capsules.upsert(it);
      return;
    }
    if (t === "remove_capsules") {
      for (const id of msg.ids) this.capsules.remove(id);
      return;
    }
    if (t === "config") {
      // allow dynamic changes (e.g., colors/opacities)
      if (msg.points && msg.points.opacity !== undefined) {
        this.points.mesh.material.opacity = msg.points.opacity;
        this.points.mesh.material.transparent = msg.points.opacity < 1.0;
      }
      if (msg.capsules && msg.capsules.opacity !== undefined) {
        this.capsules.mesh.material.opacity = msg.capsules.opacity;
        this.capsules.mesh.material.transparent = msg.capsules.opacity < 1.0;
      }
      return;
    }
    if (t === "state") {
      // optional full snapshot
      this._clear();
      if (msg.points) for (const it of msg.points) this.points.upsert(it);
      if (msg.capsules) for (const it of msg.capsules) this.capsules.upsert(it);
      return;
    }
  }

  _handleBinary(buf) {
    // Binary framing (little-endian):
    // [u8 type][u32 count][payload...]
    // type: 1=upsert_points (struct: [u64 id][f32 x][f32 y][f32 z][u32 rgb])
    //       2=upsert_capsules (struct: [u64 id][f32 ax][f32 ay][f32 az][f32 bx][f32 by][f32 bz][u32 rgb])
    const dv = new DataView(buf);
    if (dv.byteLength < 5) return;
    const type = dv.getUint8(0);
    const n = dv.getUint32(1, true);
    let off = 5;

    const readU64 = () => {
      const lo = dv.getUint32(off, true); off += 4;
      const hi = dv.getUint32(off, true); off += 4;
      return (BigInt(hi) << 32n) + BigInt(lo);
    };
    const readF32 = () => { const v = dv.getFloat32(off, true); off += 4; return v; };
    const readRGB = () => { const c = dv.getUint32(off, true); off += 4; return c & 0xffffff; };

    if (type === 1) {
      for (let i = 0; i < n; i++) {
        const id = readU64().toString();
        const x = readF32(), y = readF32(), z = readF32();
        const color = readRGB();
        this.points.upsert({ id, x, y, z, color });
      }
    } else if (type === 2) {
      for (let i = 0; i < n; i++) {
        const id = readU64().toString();
        const ax = readF32(), ay = readF32(), az = readF32();
        const bx = readF32(), by = readF32(), bz = readF32();
        const color = readRGB();
        this.capsules.upsert({ id, ax, ay, az, bx, by, bz, color });
      }
    }
  }

  _clear() {
    // recreate layers for fast purge
    this.scene.remove(this.points.mesh); this.points.mesh.geometry.dispose(); this.points.mesh.material.dispose();
    this.scene.remove(this.capsules.mesh); this.capsules.mesh.geometry.dispose(); this.capsules.mesh.material.dispose();
    this.points = new PointsLayer(this.scene, CFG.MAX_POINTS, CFG.POINTS);
    this.capsules = new CapsulesLayer(this.scene, CFG.MAX_CAPSULES, CFG.CAPSULES);
  }
}

/* ====== BOOT ====== */
window.addEventListener("DOMContentLoaded", () => {
  try { new App(); } catch (e) { console.error(e); alert("Initialization error: " + e.message); }
});
