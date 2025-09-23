import { useState } from "react";
import { Card, CardHeader, CardTitle, CardContent, CardDescription } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { useTranslation } from "react-i18next";
import { cn } from "@/shared/utils/classNames";
import { trackEvent } from "@/services/analytics/tracker";
import { submitDataErasureRequest } from "@/services/privacy/dataErasureService";
import { Logger } from "@/shared/utils/logger";
import { Alert, AlertTitle, AlertDescription } from "@/components/ui/alert";
import { Switch } from "@/components/ui/switch";
import { CheckCircleIcon, Loader2Icon } from "lucide-react";

interface DataErasureRequestFormProps {
  className?: string;
}

export const DataErasureRequestForm = ({ className }: DataErasureRequestFormProps) => {
  const { t } = useTranslation();

  const [email, setEmail] = useState("");
  const [reason, setReason] = useState("");
  const [includeBiometric, setIncludeBiometric] = useState(true);
  const [includeWeb3, setIncludeWeb3] = useState(true);
  const [includeKYC, setIncludeKYC] = useState(true);
  const [status, setStatus] = useState<"idle" | "submitting" | "success" | "error">("idle");
  const [error, setError] = useState<string | null>(null);

  const isValid = () => email.trim() !== "";

  const handleSubmit = async () => {
    if (!isValid()) return;

    setStatus("submitting");
    setError(null);

    try {
      await submitDataErasureRequest({
        email,
        reason,
        includeBiometric,
        includeWeb3,
        includeKYC,
      });

      trackEvent("privacy_erasure_requested", {
        email,
        includeBiometric,
        includeWeb3,
        includeKYC,
      });

      setStatus("success");
    } catch (err) {
      Logger.error("Erasure request failed", err);
      setStatus("error");
      setError(t("data_erasure.error"));
    }
  };

  return (
    <Card className={cn("w-full max-w-xl", className)}>
      <CardHeader>
        <CardTitle className="text-sm sm:text-base">
          {t("data_erasure.title")}
        </CardTitle>
        <CardDescription>{t("data_erasure.description")}</CardDescription>
      </CardHeader>

      <CardContent className="space-y-5">
        {status === "success" && (
          <Alert variant="success">
            <AlertTitle className="flex items-center gap-2 text-green-700">
              <CheckCircleIcon className="w-4 h-4" />
              {t("data_erasure.success_title")}
            </AlertTitle>
            <AlertDescription>{t("data_erasure.success_description")}</AlertDescription>
          </Alert>
        )}

        {status === "error" && (
          <Alert variant="destructive">
            <AlertTitle>{t("data_erasure.error_title")}</AlertTitle>
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        <div className="space-y-1">
          <Label htmlFor="email">{t("data_erasure.email")}</Label>
          <Input
            id="email"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder={t("data_erasure.email_placeholder")}
            disabled={status === "submitting" || status === "success"}
          />
        </div>

        <div className="space-y-1">
          <Label htmlFor="reason">{t("data_erasure.reason")}</Label>
          <Textarea
            id="reason"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder={t("data_erasure.reason_placeholder")}
            rows={3}
            disabled={status === "submitting" || status === "success"}
          />
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2">
          <div className="flex items-center justify-between">
            <Label>{t("data_erasure.include_biometric")}</Label>
            <Switch
              checked={includeBiometric}
              onCheckedChange={setIncludeBiometric}
              disabled={status === "submitting" || status === "success"}
            />
          </div>
          <div className="flex items-center justify-between">
            <Label>{t("data_erasure.include_web3")}</Label>
            <Switch
              checked={includeWeb3}
              onCheckedChange={setIncludeWeb3}
              disabled={status === "submitting" || status === "success"}
            />
          </div>
          <div className="flex items-center justify-between">
            <Label>{t("data_erasure.include_kyc")}</Label>
            <Switch
              checked={includeKYC}
              onCheckedChange={setIncludeKYC}
              disabled={status === "submitting" || status === "success"}
            />
          </div>
        </div>

        <Button
          onClick={handleSubmit}
          disabled={!isValid() || status === "submitting" || status === "success"}
          className="w-full"
        >
          {status === "submitting" ? (
            <>
              <Loader2Icon className="w-4 h-4 animate-spin mr-2" />
              {t("data_erasure.sending")}
            </>
          ) : (
            t("data_erasure.submit")
          )}
        </Button>
      </CardContent>
    </Card>
  );
};
