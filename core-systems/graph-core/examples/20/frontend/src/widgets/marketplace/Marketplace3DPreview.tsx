import { useEffect, useRef, useState, Suspense } from "react";
import { Canvas } from "@react-three/fiber";
import { OrbitControls, Environment, Html, useProgress, useGLTF } from "@react-three/drei";
import { Logger } from "@/shared/utils/logger";
import { cn } from "@/shared/utils/classNames";
import { LoaderIcon } from "lucide-react";
import { ErrorBoundary } from "react-error-boundary";
import { useTranslation } from "react-i18next";
import { Alert, AlertTitle, AlertDescription } from "@/components/ui/alert";

interface Marketplace3DPreviewProps {
  modelUrl: string;
  className?: string;
  autoRotate?: boolean;
  backgroundColor?: string;
  environment?: "studio" | "warehouse" | "forest";
}

const Model = ({ modelUrl }: { modelUrl: string }) => {
  const gltf = useGLTF(modelUrl, true);
  return <primitive object={gltf.scene} dispose={null} />;
};

const Loader = () => {
  const { progress } = useProgress();
  return (
    <Html center>
      <div className="flex flex-col items-center justify-center p-4 rounded bg-background shadow-md border">
        <LoaderIcon className="animate-spin mb-2 text-muted w-5 h-5" />
        <span className="text-xs text-muted-foreground">{progress.toFixed(0)}%</span>
      </div>
    </Html>
  );
};

const FallbackError = ({ error }: { error: Error }) => {
  const { t } = useTranslation();
  Logger.error("3D Preview Error", error);
  return (
    <div className="h-full w-full flex items-center justify-center p-4">
      <Alert variant="destructive">
        <AlertTitle>{t("preview_3d.error_title")}</AlertTitle>
        <AlertDescription>{t("preview_3d.error_description")}</AlertDescription>
      </Alert>
    </div>
  );
};

export const Marketplace3DPreview = ({
  modelUrl,
  className,
  autoRotate = true,
  backgroundColor = "#f5f5f5",
  environment = "studio",
}: Marketplace3DPreviewProps) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const [canvasVisible, setCanvasVisible] = useState(false);

  useEffect(() => {
    const observer = new IntersectionObserver(
      ([entry]) => setCanvasVisible(entry.isIntersecting),
      { threshold: 0.1 }
    );
    const current = containerRef.current;
    if (current) observer.observe(current);
    return () => {
      if (current) observer.unobserve(current);
    };
  }, []);

  return (
    <div
      ref={containerRef}
      className={cn("relative aspect-square w-full overflow-hidden rounded-xl", className)}
      style={{ backgroundColor }}
    >
      {canvasVisible && (
        <ErrorBoundary FallbackComponent={FallbackError}>
          <Suspense fallback={<Loader />}>
            <Canvas
              camera={{ position: [0, 1, 3], fov: 45 }}
              dpr={[1, 2]}
              gl={{ preserveDrawingBuffer: true }}
            >
              <ambientLight intensity={0.6} />
              <directionalLight position={[5, 5, 5]} intensity={1.2} castShadow />
              <Model modelUrl={modelUrl} />
              <OrbitControls
                enablePan={false}
                autoRotate={autoRotate}
                autoRotateSpeed={2}
                enableZoom={true}
              />
              <Environment preset={environment} />
            </Canvas>
          </Suspense>
        </ErrorBoundary>
      )}
    </div>
  );
};
