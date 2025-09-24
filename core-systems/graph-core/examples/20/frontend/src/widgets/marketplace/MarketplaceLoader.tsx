import React from 'react'
import { Skeleton } from '@/components/ui/skeleton'
import { cn } from '@/shared/utils/classNames'
import { motion } from 'framer-motion'

type MarketplaceLoaderProps = {
  variant?: 'grid' | 'list'
  itemCount?: number
  className?: string
}

const shimmerAnimation = {
  initial: { opacity: 0 },
  animate: { opacity: 1 },
  exit: { opacity: 0 },
  transition: { duration: 0.4, ease: 'easeInOut' },
}

export const MarketplaceLoader: React.FC<MarketplaceLoaderProps> = ({
  variant = 'grid',
  itemCount = 12,
  className,
}) => {
  const gridClasses = 'grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 xl:grid-cols-4 gap-6'
  const listClasses = 'flex flex-col gap-4'

  return (
    <motion.div
      {...shimmerAnimation}
      role="status"
      aria-live="polite"
      className={cn(
        'relative w-full animate-pulse',
        variant === 'grid' ? gridClasses : listClasses,
        className
      )}
    >
      {Array.from({ length: itemCount }).map((_, i) => (
        <LoaderItem key={i} variant={variant} />
      ))}
    </motion.div>
  )
}

const LoaderItem: React.FC<{ variant: 'grid' | 'list' }> = ({ variant }) => {
  return (
    <div
      className={cn(
        'border rounded-md bg-muted p-4 shadow-sm',
        variant === 'list' && 'flex items-center gap-4'
      )}
    >
      <Skeleton className={cn('rounded-md', variant === 'grid' ? 'h-40 w-full mb-4' : 'h-20 w-20')} />
      <div className={cn('flex flex-col gap-2', variant === 'grid' ? 'w-full' : 'flex-1')}>
        <Skeleton className="h-4 w-3/4" />
        <Skeleton className="h-4 w-1/2" />
        <div className="flex gap-2 mt-1">
          <Skeleton className="h-6 w-16 rounded-full" />
          <Skeleton className="h-6 w-20 rounded-full" />
        </div>
      </div>
    </div>
  )
}

export default MarketplaceLoader
