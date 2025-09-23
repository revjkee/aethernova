import { useEffect, useState, useCallback } from "react";
import { Button } from "@/components/ui/button";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { QRCodeModal } from "@/components/ui/qr-code";
import { useTranslation } from "react-i18next";
import { WalletIcon, LoaderIcon, ShieldXIcon, CheckCircleIcon } from "lucide-react";
import { connectWallet, getWalletStatus, disconnectWallet } from "@/services/web3/walletManager";
import { WalletType, WalletConnectionStatus } from "@/types/web3";
import { cn } from "@/shared/utils/classNames";
import { Logger } from "@/shared/utils/logger";
import { useUserContext } from "@/shared/context/UserContext";
import { trackEvent } from "@/services/analytics/tracker";

interface WalletConnectPromptProps {
  className?: string;
  onConnected?: () => void;
  required?: boolean;
}

export const WalletConnectPrompt = ({
  className,
  onConnected,
  required = false,
}: WalletConnectPromptProps) => {
  const { user } = useUserContext();
  const { t } = useTranslation();

  const [status, setStatus] = useState<WalletConnectionStatus>("disconnected");
  const [error, setError] = useState<string | null>(null);
  const [walletType, setWalletType] = useState<WalletType | null>(null);

  const initWalletCheck = useCallback(async () => {
    try {
      setStatus("checking");
      const result = await getWalletStatus(user?.id || "");
      setStatus(result.status);
      setWalletType(result.walletType || null);
    } catch (err) {
      Logger.warn("wallet check failed", err);
      setStatus("disconnected");
    }
  }, [user?.id]);

  useEffect(() => {
    initWalletCheck();
  }, [initWalletCheck]);

  const handleConnect = async (type: WalletType) => {
    try {
      setError(null);
      setWalletType(type);
      setStatus("connecting");
      const result = await connectWallet(type, user?.id || "");

      if (result.success) {
        setStatus("connected");
        trackEvent("wallet_connected", {
          userId: user?.id,
          walletType: type,
        });
        onConnected?.();
      } else {
        throw new Error(result.message || "Unknown error");
      }
    } catch (err: any) {
      Logger.error("wallet connect failed", err);
      setStatus("disconnected");
      setError(t("wallet.connection_failed", { reason: err.message }));
    }
  };

  const handleDisconnect = async () => {
    try {
      await disconnectWallet();
      setStatus("disconnected");
      setWalletType(null);
    } catch (err) {
      Logger.error("wallet disconnect failed", err);
    }
  };

  const renderStatus = () => {
    switch (status) {
      case "checking":
        return <LoaderIcon className="animate-spin text-muted w-5 h-5" />;
      case "connected":
        return <CheckCircleIcon className="text-green-600 w-5 h-5" />;
      case "error":
        return <ShieldXIcon className="text-red-500 w-5 h-5" />;
      default:
        return <WalletIcon className="w-5 h-5" />;
    }
  };

  return (
    <div className={cn("rounded-xl border p-6 space-y-4", className)}>
      <div className="flex items-center gap-3">
        {renderStatus()}
        <div className="text-sm">
          {status === "connected"
            ? t("wallet.connected", { type: walletType })
            : t("wallet.prompt")}
        </div>
      </div>

      {status === "disconnected" || status === "error" ? (
        <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
          <Button onClick={() => handleConnect("metamask")} variant="outline">
            MetaMask
          </Button>
          <Button onClick={() => handleConnect("walletconnect")} variant="outline">
            WalletConnect
          </Button>
          <Button onClick={() => handleConnect("ton")} variant="outline">
            TON Wallet
          </Button>
        </div>
      ) : null}

      {status === "connecting" && (
        <QRCodeModal title={t("wallet.connecting")} description={t("wallet.qr_scan")} />
      )}

      {error && (
        <Alert variant="destructive">
          <AlertTitle>{t("wallet.connection_failed_title")}</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {status === "connected" && (
        <div className="flex justify-end">
          <Button variant="ghost" size="sm" onClick={handleDisconnect}>
            {t("wallet.disconnect")}
          </Button>
        </div>
      )}
    </div>
  );
};
