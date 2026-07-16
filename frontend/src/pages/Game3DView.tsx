// frontend/src/pages/Game3DView.tsx
import * as React from "react";
import type { FC } from "react";
import { motion } from "framer-motion";

// ВАЖНО: библиотеки r3f/drei должны быть в зависимостях проекта.
// Предполагается наличие Tailwind и shadcn/ui (кнопки, карточки и т.п.).
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { Badge } from "@/components/ui/badge";
import { Slider } from "@/components/ui/slider";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";

// Динамический импорт Canvas/доп. компонентов для SSR-совместимости
const R3F = React.lazy(async () => {
  const fiber = await import("@react-three/fiber");
  return { default: fiber.Canvas };
});
const Drei = React.lazy(async () => import("@react-three/drei"));
const PerfMod = React.lazy(async () => import("r3f-perf").catch(() => ({ default: () => null })));

// Типы пропсов страницы
export type Game3DViewProps = {
  modelUrl?: string;                 // URL glTF/GLB модели (необязательно)
  hdrEnvUrl?: string;                // URL HDRI окружения (необязательно)
  initialCamera?: {
    position?: [number, number, number];
    target?: [number, number, number];
    fov?: number;
  };
  className?: string;
};

// Вспомогательная проверка WebGL
function isWebGLSupported(): boolean {
  if (typeof window === "undefined") return true; // на сервере — пропускаем
  try {
    const canvas = document.createElement("canvas");
    const gl =
      canvas.getContext("webgl2") ??
      canvas.getContext("webgl") ??
      canvas.getContext("experimental-webgl");
    return !!gl;
  } catch {
    return false;
  }
}

// Хук управления качеством в рантайме
function useQualityController() {
  const [dpr, setDpr] = React.useState<[number, number]>([1, 2]);
  const [shadows, setShadows] = React.useState<boolean>(true);
  const [perfOverlay, setPerfOverlay] = React.useState<boolean>(false);
  const [paused, setPaused] = React.useState<boolean>(false);

  // Горячие клавиши: Q — цикл DPR, P — пауза, O — perf overlay, H — тени
  React.useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.repeat) return;
      switch (e.key.toLowerCase()) {
        case "q":
          setDpr((prev) => (prev[1] === 2 ? [0.75, 1.5] : prev[1] === 1.5 ? [1, 1] : [1, 2]));
          break;
        case "p":
          setPaused((p) => !p);
          break;
        case "o":
          setPerfOverlay((p) => !p);
          break;
        case "h":
          setShadows((s) => !s);
          break;
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  return {
    dpr,
    setDpr,
    shadows,
    setShadows,
    perfOverlay,
    setPerfOverlay,
    paused,
    setPaused,
  };
}

// Компонент сцены. Использует drei, но объявляем типы через any из-за ленивого импорта
const Scene: FC<{
  DreiNS: any;
  modelUrl?: string;
  hdrEnvUrl?: string;
  camera: Required<NonNullable<Game3DViewProps["initialCamera"]>>;
  shadows: boolean;
}> = ({ DreiNS, modelUrl, hdrEnvUrl, camera, shadows }) => {
  const { OrbitControls, Environment, ContactShadows, useGLTF, Stage, Html } = DreiNS;

  // Прелоад модели (если задана)
  const Model: FC = React.useMemo(() => {
    if (!modelUrl) return () => null;
    const Comp: FC = () => {
      const gltf = useGLTF(modelUrl, true);
      return <primitive object={gltf.scene} dispose={null} />;
    };
    // @ts-expect-error — у drei есть статический метод дрейна кэша
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (useGLTF as any).preload?.(modelUrl);
    return Comp;
  }, [modelUrl, useGLTF]);

  return (
    <>
      <DreiNS.PerspectiveCamera
        makeDefault
        fov={camera.fov}
        position={camera.position}
        // вращаемся вокруг целевой точки
      />
      <group>
        {/* Базовое освещение */}
        <hemisphereLight intensity={0.6} color="#ffffff" groundColor="#444444" />
        <directionalLight
          position={[5, 10, 5]}
          castShadow={shadows}
          intensity={1.2}
          shadow-mapSize-width={2048}
          shadow-mapSize-height={2048}
        />
        {/* Окружение HDRI или Stage */}
        {hdrEnvUrl ? (
          <Environment files={hdrEnvUrl} background={false} />
        ) : (
          <Stage
            adjustCamera={false}
            intensity={1}
            environment="city"
            shadows={shadows ? { type: "contact", opacity: 0.6, blur: 2.5 } : false}
          >
            <mesh receiveShadow rotation-x={-Math.PI / 2}>
              <planeGeometry args={[100, 100]} />
              <meshStandardMaterial color="#cfcfcf" />
            </mesh>
          </Stage>
        )}

        {/* Модель (если есть) */}
        {modelUrl ? (
          <React.Suspense
            fallback={
              <Html center>
                <div className="rounded-md bg-background/80 px-3 py-2 text-sm shadow">
                  Загрузка модели…
                </div>
              </Html>
            }
          >
            <group position={[0, 0, 0]}>
              <Model />
            </group>
          </React.Suspense>
        ) : (
          // Демо-геометрия, если модель не передана
          <mesh castShadow position={[0, 1, 0]}>
            <boxGeometry args={[1, 1, 1]} />
            <meshStandardMaterial color="#4b9ce2" metalness={0.2} roughness={0.4} />
          </mesh>
        )}

        {/* Контактные тени */}
        {shadows && (
          <ContactShadows
            frames={1}
            position={[0, 0, 0]}
            opacity={0.5}
            scale={10}
            blur={2.5}
            far={4}
          />
        )}
      </group>

      {/* Управление камерой */}
      <OrbitControls
        enableDamping
        dampingFactor={0.07}
        target={camera.target}
        makeDefault
      />
    </>
  );
};

// Оверлей управления качеством/состоянием
const OverlayControls: FC<{
  dpr: [number, number];
  setDpr: (v: [number, number]) => void;
  shadows: boolean;
  setShadows: (v: boolean) => void;
  perfOverlay: boolean;
  setPerfOverlay: (v: boolean) => void;
  paused: boolean;
  setPaused: (v: boolean) => void;
}> = ({ dpr, setDpr, shadows, setShadows, perfOverlay, setPerfOverlay, paused, setPaused }) => {
  // Преобразуем DPR в удобный слайдер (0.75—2)
  const dprValue = React.useMemo(() => Math.max(0.5, Math.min(2.5, dpr[1])), [dpr]);

  return (
    <Card className="w-full md:w-80 border bg-background/80 backdrop-blur supports-[backdrop-filter]:bg-background/60">
      <CardHeader>
        <CardTitle className="text-base">Панель</CardTitle>
        <CardDescription>Качество, тени, пауза кадра, перфоманс</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div>
          <div className="mb-2 flex items-center justify-between">
            <span className="text-sm">DPR</span>
            <Badge variant="secondary">{dprValue.toFixed(2)}x</Badge>
          </div>
          <Slider
            value={[dprValue]}
            min={0.75}
            max={2}
            step={0.05}
            onValueChange={([v]) => setDpr([v, v])}
            aria-label="Device Pixel Ratio"
          />
        </div>

        <Separator />

        <div className="flex items-center justify-between">
          <span className="text-sm">Тени</span>
          <Button variant={shadows ? "default" : "outline"} size="sm" onClick={() => setShadows(!shadows)}>
            {shadows ? "Вкл" : "Выкл"}
          </Button>
        </div>

        <div className="flex items-center justify-between">
          <span className="text-sm">Пауза рендера</span>
          <Button variant={paused ? "default" : "outline"} size="sm" onClick={() => setPaused(!paused)}>
            {paused ? "Пауза" : "Идёт"}
          </Button>
        </div>

        <div className="flex items-center justify-between">
          <span className="text-sm">Performance</span>
          <Button
            variant={perfOverlay ? "default" : "outline"}
            size="sm"
            onClick={() => setPerfOverlay(!perfOverlay)}
          >
            {perfOverlay ? "Показать" : "Скрыть"}
          </Button>
        </div>

        <Separator />

        <div className="text-xs text-muted-foreground">
          Горячие клавиши: Q — DPR, H — тени, P — пауза, O — перф.
        </div>
      </CardContent>
    </Card>
  );
};

// Главная страница просмотра 3D
const Game3DView: FC<Game3DViewProps> = ({
  modelUrl,
  hdrEnvUrl,
  className,
  initialCamera = {
    position: [4, 3, 6],
    target: [0, 1, 0],
    fov: 50,
  },
}) => {
  const [webglOk, setWebglOk] = React.useState(true);
  const wrapRef = React.useRef<HTMLDivElement | null>(null);

  const {
    dpr, setDpr, shadows, setShadows, perfOverlay, setPerfOverlay, paused, setPaused,
  } = useQualityController();

  React.useEffect(() => {
    setWebglOk(isWebGLSupported());
  }, []);

  return (
    <div className={["relative min-h-screen w-full bg-background", className].filter(Boolean).join(" ")}>
      {/* Верхняя панель заголовка */}
      <div className="sticky top-0 z-30 border-b bg-background/70 backdrop-blur supports-[backdrop-filter]:bg-background/50">
        <div className="mx-auto w-full max-w-7xl px-4 sm:px-6 lg:px-8">
          <div className="flex h-14 items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="h-5 w-5 rounded bg-foreground/80" aria-hidden />
              <span className="text-sm font-semibold tracking-tight">Game3D Viewer</span>
              <Badge variant="outline">beta</Badge>
            </div>
            <TooltipProvider delayDuration={150}>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button variant="ghost" size="sm">Справка</Button>
                </TooltipTrigger>
                <TooltipContent>
                  <p className="max-w-xs text-sm">
                    Управление мышью: вращение — ЛКМ, панорамирование — Shift+ЛКМ, масштаб — колесо.
                  </p>
                </TooltipContent>
              </Tooltip>
            </TooltipProvider>
          </div>
        </div>
      </div>

      {/* Контент */}
      <div className="mx-auto grid w-full max-w-7xl grid-cols-1 gap-4 px-4 py-4 sm:px-6 lg:px-8 lg:grid-cols-[1fr_22rem]">
        <div ref={wrapRef} className="relative aspect-video w-full overflow-hidden rounded-2xl border bg-muted/20">
          {!webglOk ? (
            <div className="flex h-full w-full items-center justify-center">
              <Card className="m-4 max-w-md">
                <CardHeader>
                  <CardTitle>WebGL недоступен</CardTitle>
                  <CardDescription>Пожалуйста, обновите драйверы или откройте страницу в другом браузере.</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="text-sm text-muted-foreground">
                    Canvas рендерер не инициализировался. Попробуйте Chrome/Firefox/Edge на настольном ПК.
                  </div>
                </CardContent>
              </Card>
            </div>
          ) : (
            <React.Suspense
              fallback={
                <div className="flex h-full w-full items-center justify-center">
                  <motion.div
                    initial={{ opacity: 0, y: 8 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="rounded-md bg-background/80 px-4 py-2 text-sm shadow"
                  >
                    Инициализация рендера…
                  </motion.div>
                </div>
              }
            >
              {/* Canvas */}
              <R3F
                // Управление частотой рендера: когда paused — не рендерим кадры
                frameloop={paused ? "never" : "always"}
                dpr={dpr}
                shadows={shadows}
                gl={{
                  antialias: true,
                  powerPreference: "high-performance",
                  alpha: true,
                  stencil: false,
                  depth: true,
                }}
                camera={{ fov: initialCamera.fov, position: initialCamera.position }}
                className="h-full w-full"
              >
                <React.Suspense fallback={null}>
                  <Drei>
                    {({ default: DreiNS }: any) => (
                      <Scene
                        DreiNS={DreiNS}
                        modelUrl={modelUrl}
                        hdrEnvUrl={hdrEnvUrl}
                        camera={{
                          position: initialCamera.position ?? [4, 3, 6],
                          target: initialCamera.target ?? [0, 1, 0],
                          fov: initialCamera.fov ?? 50,
                        }}
                        shadows={shadows}
                      />
                    )}
                  </Drei>
                </React.Suspense>

                {/* Освещение для читаемости даже без HDR */}
                <color attach="background" args={["#f8fafc"]} />

                {/* Перфоманс HUD опционально */}
                {perfOverlay ? (
                  <React.Suspense fallback={null}>
                    {/* @ts-expect-error типы могут отсутствовать, безопасно по умолчанию */}
                    <PerfMod position="top-left" minimal deepAnalyze />
                  </React.Suspense>
                ) : null}
              </R3F>
            </React.Suspense>
          )}
        </div>

        {/* Боковая панель */}
        <div className="sticky top-16 h-fit space-y-4">
          <OverlayControls
            dpr={dpr}
            setDpr={setDpr}
            shadows={shadows}
            setShadows={setShadows}
            perfOverlay={perfOverlay}
            setPerfOverlay={setPerfOverlay}
            paused={paused}
            setPaused={setPaused}
          />

          <Card>
            <CardHeader>
              <CardTitle className="text-base">Сеанс</CardTitle>
              <CardDescription>Текущие параметры</CardDescription>
            </CardHeader>
            <CardContent className="space-y-2 text-sm text-muted-foreground">
              <div className="flex items-center justify-between">
                <span>Модель</span>
                <span className="truncate">{modelUrl ?? "демо-куб"}</span>
              </div>
              <div className="flex items-center justify-between">
                <span>Окружение</span>
                <span className="truncate">{hdrEnvUrl ?? "Stage: city"}</span>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
};

export default Game3DView;

/**
 * ПРИМЕЧАНИЯ ПО ПРОИЗВОДСТВУ:
 * - Для загрузки больших GLB используйте CDN и включите HTTP/2/3 + кеширование ETag/immutable.
 * - Для анимаций моделей подключайте mixer и clock из drei/useAnimations.
 * - Для интерактива добавляйте raycaster-интеракции через onPointerOver/onClick на мешах.
 * - Для больших сцен используйте BVH (three-mesh-bvh) и InstancedMesh.
 * - Для PBR окружения рекомендуется HDRI (RGBE/EXR) и PMREM из drei/Environment.
 * - Для сохранения камеры между визитами сохраняйте позицию/target в localStorage.
 */
