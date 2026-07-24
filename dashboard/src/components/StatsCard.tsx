'use client';

import Link from 'next/link';
import { cn } from '@/lib/utils';
import type { ReactNode } from 'react';

interface StatsCardProps {
  title: string;
  value: string | number;
  subtitle?: ReactNode;
  href?: string;
  icon?: ReactNode;
  trend?: {
    value: number;
    label?: string;
  };
  progress?: {
    current: number;
    max: number | null; // null = unlimited
  };
  className?: string;
}

export function StatsCard({
  title,
  value,
  subtitle,
  href,
  icon,
  trend,
  progress,
  className,
}: StatsCardProps) {
  const content = (
    <div
      className={cn(
        'card p-5 hover:border-border-secondary transition-colors',
        href && 'cursor-pointer',
        className
      )}
    >
      <div className="flex items-start justify-between">
        <span className="text-sm font-medium text-text-tertiary uppercase tracking-wide">
          {title}
        </span>
        {icon && <div className="text-text-tertiary">{icon}</div>}
      </div>

      <div className="mt-3">
        <span className="text-3xl font-bold text-text-primary">{value}</span>
        {trend && (
          <span
            className={cn(
              'ml-2 text-sm',
              trend.value > 0 ? 'text-success' : trend.value < 0 ? 'text-error' : 'text-text-tertiary'
            )}
          >
            {trend.value > 0 ? '+' : ''}
            {trend.value}
            {trend.label && ` ${trend.label}`}
          </span>
        )}
      </div>

      {subtitle && <div className="mt-2 text-sm text-text-secondary">{subtitle}</div>}

      {progress && (
        <div className="mt-3">
          <div className="h-2 bg-bg-tertiary rounded-full overflow-hidden">
            <div
              className={cn(
                'h-full rounded-full transition-all',
                progress.max === null
                  ? 'bg-success'
                  : progress.current / progress.max > 0.8
                  ? 'bg-warning'
                  : 'bg-primary-500'
              )}
              style={{
                width: progress.max === null ? '100%' : `${Math.min((progress.current / progress.max) * 100, 100)}%`,
              }}
            />
          </div>
          <div className="mt-1 text-xs text-text-tertiary">
            {progress.max === null ? 'Unlimited' : `${progress.current}/${progress.max}`}
          </div>
        </div>
      )}
    </div>
  );

  if (href) {
    return <Link href={href}>{content}</Link>;
  }

  return content;
}

export function StatsCardSkeleton() {
  return (
    <div className="card p-5">
      <div className="skeleton h-4 w-24" />
      <div className="mt-3 skeleton h-8 w-20" />
      <div className="mt-3 skeleton h-4 w-32" />
    </div>
  );
}
