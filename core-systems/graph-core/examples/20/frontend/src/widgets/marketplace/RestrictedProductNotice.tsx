import { useEffect, useState } from "react";
import { Alert, AlertTitle, AlertDescription } from "@/components/ui/alert";
import { ExclamationTriangleIcon } from "@radix-ui/react-icons";
import { getUserComplianceStatus } from "@/services/api/userService";
import { useTranslation } from "react-i18next";
import { Logger } from "@/shared/utils/logger";
import { FeatureFlag } from "@/shared/feature/flags";
import { useFeature } from "@/shared/hooks/useFeature";
import { RestrictedReason } from "@/types/compliance";
import { cn } from "@/shared/utils/classNames";
import { useUserContext } from "@/shared/context/UserContext";

interface RestrictedProductNoticeProps {
  productId: string;
  className?: string;
}

export const RestrictedProductNotice = ({
  productId,
  className,
}: RestrictedProductNoticeProps) => {
  const [restricted, setRestricted] = useState<boolean>(false);
  const [reason, setReason] = useState<RestrictedReason | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const { user } = useUserContext();
  const { t } = useTranslation();
  const regionCheckEnabled = useFeature(FeatureFlag.RegionRestriction);
  const kycCheckEnabled = useFeature(FeatureFlag.KYCCompliance);
  const ageCheckEnabled = useFeature(FeatureFlag.AgeRestriction);

  useEffect(() => {
    const checkRestrictions = async () => {
      if (!user?.id) return;
      try {
        setLoading(true);
        const result = await getUserComplianceStatus({
          userId: user.id,
          productId,
        });

        if (result.restricted) {
          setRestricted(true);
          setReason(result.reason);
        } else {
          setRestricted(false);
          setReason(null);
        }
      } catch (err) {
        Logger.error("RestrictedProductNotice: Compliance check failed", err);
        setError(t("errors.restriction_check_failed"));
      } finally {
        setLoading(false);
      }
    };

    checkRestrictions();
  }, [user?.id, productId]);

  if (loading || !regionCheckEnabled) {
    return null;
  }

  if (error) {
    return (
      <Alert variant="destructive" className={cn("mt-4", className)}>
        <ExclamationTriangleIcon className="h-5 w-5" />
        <AlertTitle>{t("errors.title")}</AlertTitle>
        <AlertDescription>{error}</AlertDescription>
      </Alert>
    );
  }

  if (!restricted || !reason) {
    return null;
  }

  const getRestrictionMessage = () => {
    switch (reason) {
      case "region_blocked":
        return t("restrictions.region");
      case "kyc_pending":
        return t("restrictions.kyc_pending");
      case "kyc_failed":
        return t("restrictions.kyc_failed");
      case "age_restricted":
        return t("restrictions.age");
      case "compliance_violation":
        return t("restrictions.compliance_violation");
      default:
        return t("restrictions.generic");
    }
  };

  return (
    <Alert variant="warning" className={cn("mt-4", className)} role="alert">
      <ExclamationTriangleIcon className="h-5 w-5 text-yellow-600" />
      <AlertTitle>{t("restrictions.notice_title")}</AlertTitle>
      <AlertDescription>{getRestrictionMessage()}</AlertDescription>
    </Alert>
  );
};
