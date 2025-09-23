import React, { useState, useEffect, useCallback } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { enrollInCourse, checkEnrollmentStatus } from '@/services/api/eduAPI';
import { Button } from '@/shared/components/Button';
import { Spinner } from '@/shared/components/Spinner';
import { useTranslation } from 'react-i18next';

interface Props {
  courseId: string;
  userId: string;
  onEnrolled?: () => void;
  className?: string;
}

const CourseEnrollmentButton: React.FC<Props> = ({
  courseId,
  userId,
  onEnrolled,
  className,
}) => {
  const { t } = useTranslation();
  const [isEnrolled, setIsEnrolled] = useState<boolean | null>(null);
  const queryClient = useQueryClient();

  const { mutateAsync: enrollMutate, isLoading: isEnrolling } = useMutation(
    () => enrollInCourse(courseId, userId),
    {
      onSuccess: () => {
        setIsEnrolled(true);
        onEnrolled && onEnrolled();
        queryClient.invalidateQueries(['enrollmentStatus', courseId, userId]);
      },
      onError: () => {
        // Ошибка может обрабатываться отдельно или через уведомления
      },
    }
  );

  useEffect(() => {
    let isMounted = true;
    checkEnrollmentStatus(courseId, userId).then((status) => {
      if (isMounted) setIsEnrolled(status);
    }).catch(() => {
      if (isMounted) setIsEnrolled(false);
    });
    return () => { isMounted = false; };
  }, [courseId, userId]);

  const handleEnrollClick = useCallback(() => {
    if (isEnrolled || isEnrolling) return;
    enrollMutate();
  }, [isEnrolled, isEnrolling, enrollMutate]);

  if (isEnrolled === null) {
    return (
      <Button variant="primary" className={className} disabled>
        <Spinner size="sm" /> {t('edu.enrollmentChecking')}
      </Button>
    );
  }

  if (isEnrolled) {
    return (
      <Button variant="secondary" className={className} disabled>
        {t('edu.alreadyEnrolled')}
      </Button>
    );
  }

  return (
    <Button
      variant="primary"
      className={className}
      onClick={handleEnrollClick}
      disabled={isEnrolling}
      aria-disabled={isEnrolling}
    >
      {isEnrolling ? (
        <>
          <Spinner size="sm" /> {t('edu.enrolling')}
        </>
      ) : (
        t('edu.enrollNow')
      )}
    </Button>
  );
};

export default React.memo(CourseEnrollmentButton);
