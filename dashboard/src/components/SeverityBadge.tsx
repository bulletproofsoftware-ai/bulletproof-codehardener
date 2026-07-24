'use client';

import { cn } from '@/lib/utils';
import type { FindingSeverity } from '@/types';

interface SeverityBadgeProps {
  severity: FindingSeverity;
  size?: 'sm' | 'md';
  showDot?: boolean;
}

const severityConfig: Record<
  FindingSeverity,
  { label: string; bgClass: string; textClass: string; dotClass: string }
> = {
  critical: {
    label: 'Critical',
    bgClass: 'bg-error/10',
    textClass: 'text-error',
    dotClass: 'bg-error',
  },
  high: {
    label: 'High',
    bgClass: 'bg-orange-500/10',
    textClass: 'text-orange-500',
    dotClass: 'bg-orange-500',
  },
  medium: {
    label: 'Medium',
    bgClass: 'bg-warning/10',
    textClass: 'text-warning',
    dotClass: 'bg-warning',
  },
  low: {
    label: 'Low',
    bgClass: 'bg-info/10',
    textClass: 'text-info',
    dotClass: 'bg-info',
  },
  info: {
    label: 'Info',
    bgClass: 'bg-text-tertiary/10',
    textClass: 'text-text-secondary',
    dotClass: 'bg-text-tertiary',
  },
};

export function SeverityBadge({ severity, size = 'md', showDot = false }: SeverityBadgeProps) {
  const config = severityConfig[severity];

  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded font-medium',
        config.bgClass,
        config.textClass,
        size === 'sm' ? 'px-1.5 py-0.5 text-xs' : 'px-2 py-1 text-xs'
      )}
    >
      {showDot && <span className={cn('w-1.5 h-1.5 rounded-full', config.dotClass)} />}
      {config.label}
    </span>
  );
}

export function SeverityDot({
  severity,
  size = 'md',
}: {
  severity: FindingSeverity;
  size?: 'sm' | 'md';
}) {
  const config = severityConfig[severity];
  return (
    <span
      className={cn(
        'inline-block rounded-full',
        config.dotClass,
        size === 'sm' ? 'w-1.5 h-1.5' : 'w-2 h-2'
      )}
    />
  );
}
