import { clsx, type ClassValue } from 'clsx';

export function cn(...inputs: ClassValue[]) {
  return clsx(inputs);
}

export function formatDate(date: string | Date): string {
  return new Intl.DateTimeFormat('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  }).format(new Date(date));
}

export function formatDateTime(date: string | Date): string {
  return new Intl.DateTimeFormat('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  }).format(new Date(date));
}

export function formatRelativeTime(date: string | Date): string {
  const now = new Date();
  const then = new Date(date);
  const seconds = Math.floor((now.getTime() - then.getTime()) / 1000);

  if (seconds < 60) return 'just now';
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  if (seconds < 604800) return `${Math.floor(seconds / 86400)}d ago`;
  return formatDate(date);
}

export function formatNumber(num: number): string {
  if (num >= 1000000) {
    return `${(num / 1000000).toFixed(1)}M`;
  }
  if (num >= 1000) {
    return `${(num / 1000).toFixed(1)}K`;
  }
  return num.toString();
}

export function getScoreLevel(score: number): 'excellent' | 'good' | 'medium' | 'high' | 'critical' {
  if (score >= 900) return 'excellent';
  if (score >= 750) return 'good';
  if (score >= 500) return 'medium';
  if (score >= 250) return 'high';
  return 'critical';
}

export function getScoreLabel(score: number): string {
  const level = getScoreLevel(score);
  const labels = {
    excellent: 'Excellent',
    good: 'Good',
    medium: 'Medium Risk',
    high: 'High Risk',
    critical: 'Critical',
  };
  return labels[level];
}

export function getSeverityColor(severity: string): string {
  const colors: Record<string, string> = {
    critical: 'text-error',
    high: 'text-orange-500',
    medium: 'text-warning',
    low: 'text-info',
    info: 'text-text-secondary',
  };
  return colors[severity.toLowerCase()] ?? 'text-text-secondary';
}

export function getSeverityBadgeClass(severity: string): string {
  const classes: Record<string, string> = {
    critical: 'badge-error',
    high: 'bg-orange-500/10 text-orange-500',
    medium: 'badge-warning',
    low: 'badge-info',
    info: 'badge-neutral',
  };
  return classes[severity.toLowerCase()] ?? 'badge-neutral';
}

export function truncate(str: string, length: number): string {
  if (str.length <= length) return str;
  return `${str.substring(0, length)}...`;
}

export function generateApiKey(): string {
  const array = new Uint8Array(24);
  crypto.getRandomValues(array);
  return 'ch_' + Array.from(array, b => b.toString(36).padStart(2, '0')).join('').slice(0, 32);
}
