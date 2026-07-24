'use client';

import { cn } from '@/lib/utils';
import type { FindingStatus } from '@/types';

interface StatusBadgeProps {
  status: FindingStatus | string;
  size?: 'sm' | 'md';
}

const statusConfig: Record<
  string,
  { label: string; bgClass: string; textClass: string }
> = {
  open: {
    label: 'Open',
    bgClass: 'bg-error/10',
    textClass: 'text-error',
  },
  fixed: {
    label: 'Fixed',
    bgClass: 'bg-success/10',
    textClass: 'text-success',
  },
  ignored: {
    label: 'Ignored',
    bgClass: 'bg-text-tertiary/10',
    textClass: 'text-text-secondary',
  },
  false_positive: {
    label: 'False Positive',
    bgClass: 'bg-violet-500/10',
    textClass: 'text-violet-400',
  },
  deferred: {
    label: 'Deferred',
    bgClass: 'bg-amber-500/10',
    textClass: 'text-amber-400',
  },
};

const fallbackConfig = {
  label: 'Unknown',
  bgClass: 'bg-text-tertiary/10',
  textClass: 'text-text-secondary',
};

export function StatusBadge({ status, size = 'md' }: StatusBadgeProps) {
  const config = statusConfig[status] || fallbackConfig;

  return (
    <span
      className={cn(
        'inline-flex items-center rounded font-medium',
        config.bgClass,
        config.textClass,
        size === 'sm' ? 'px-1.5 py-0.5 text-xs' : 'px-2 py-1 text-xs'
      )}
    >
      {config.label}
    </span>
  );
}
