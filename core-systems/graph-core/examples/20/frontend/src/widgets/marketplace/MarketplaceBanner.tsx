import { useEffect, useState, useRef } from "react";
import { cn } from "@/shared/utils/classNames";
import { useWebAppTheme } from "@/shared/telegram/useWebAppTheme";
import { trackEvent } from "@/services/analytics/tracker";
import { fetchPromotionalBanners } from "@/services/api/bannerService";
import { BannerContent, BannerClickPayload } from "@/types/marketplace";
import { Spinner } from "@/shared/components/Spinner";
import { Button } from "@/shared/components/Button";
import { useInterval } from "@/shared/hooks/useInterval";
import { useBreakpoint } from "@/shared/hooks/useBreakpoint";

interface MarketplaceBannerProps {
  className?: string;
  userId: string;
  context?: string;
}

export const MarketplaceBanner = ({
  className,
  userId,
  context = "homepage",
}: MarketplaceBannerProps) => {
  const [banners, setBanners] = useState<BannerContent[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [activeIndex, setActiveIndex] = useState<number>(0);
  const { theme } = useWebAppTheme();
  const containerRef = useRef<HTMLDivElement | null>(null);
  const breakpoint = useBreakpoint();

  const ROTATION_INTERVAL_MS = 7000;

  useInterval(() => {
    setActiveIndex((prev) => (banners.length > 0 ? (prev + 1) % banners.length : 0));
  }, banners.length > 1 ? ROTATION_INTERVAL_MS : null);

  const handleBannerClick = (banner: BannerContent) => {
    const payload: BannerClickPayload = {
      bannerId: banner.id,
      userId,
      timestamp: new Date().toISOString(),
      context,
    };
    trackEvent("banner_click", payload);
    if (banner.targetUrl) {
      window.open(banner.targetUrl, "_blank", "noopener,noreferrer");
    }
  };

  useEffect(() => {
    const loadBanners = async () => {
      try {
        setLoading(true);
        const data = await fetchPromotionalBanners(context, userId);
        setBanners(data || []);
      } catch (err) {
        console.error("Failed to load banners", err);
        setBanners([]);
      } finally {
        setLoading(false);
      }
    };
    loadBanners();
  }, [userId, context]);

  if (loading) {
    return (
      <div
        className={cn(
          "w-full h-[180px] sm:h-[240px] flex items-center justify-center bg-muted rounded-xl",
          className
        )}
      >
        <Spinner size="lg" />
      </div>
    );
  }

  if (banners.length === 0) {
    return null;
  }

  const currentBanner = banners[activeIndex];

  return (
    <div
      ref={containerRef}
      className={cn(
        "relative overflow-hidden w-full rounded-2xl border border-border transition-shadow hover:shadow-xl",
        className
      )}
      style={{
        backgroundColor: currentBanner.bgColor || theme.backgroundColor || "#ffffff",
      }}
    >
      <img
        src={currentBanner.imageUrl}
        alt={currentBanner.title}
        className="absolute top-0 left-0 w-full h-full object-cover opacity-80"
        loading="lazy"
      />

      <div className="relative z-10 flex flex-col justify-between h-full p-6 sm:p-8 text-white backdrop-blur-md bg-black/30 rounded-2xl">
        <div className="space-y-1">
          <h3 className="text-xl sm:text-2xl font-bold drop-shadow">{currentBanner.title}</h3>
          <p className="text-sm sm:text-base opacity-90">{currentBanner.subtitle}</p>
        </div>

        {currentBanner.ctaLabel && (
          <div className="mt-4 sm:mt-6">
            <Button
              variant="accent"
              size={breakpoint === "sm" ? "sm" : "md"}
              onClick={() => handleBannerClick(currentBanner)}
              className="shadow-md hover:shadow-lg"
            >
              {currentBanner.ctaLabel}
            </Button>
          </div>
        )}
      </div>
    </div>
  );
};
