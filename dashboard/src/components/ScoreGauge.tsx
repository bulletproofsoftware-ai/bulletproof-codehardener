'use client';

import { cn } from '@/lib/utils';

interface ScoreGaugeProps {
  score: number;
  scoreRaw?: number;
  size?: 'sm' | 'md' | 'lg';
  showLabel?: boolean;
  trend?: 'up' | 'down' | 'stable';
}

export function ScoreGauge({ score: rawScore, scoreRaw, size = 'md', showLabel = true, trend }: ScoreGaugeProps) {
  const score = typeof rawScore === 'number' && !isNaN(rawScore) ? rawScore : 0;
  const getScoreLevel = (score: number) => {
    if (score >= 900) return 'excellent';
    if (score >= 750) return 'good';
    if (score >= 500) return 'medium';
    if (score >= 250) return 'high';
    return 'critical';
  };

  const getScoreLabel = (level: string) => {
    const labels: Record<string, string> = {
      excellent: 'Excellent',
      good: 'Good',
      medium: 'Medium Risk',
      high: 'High Risk',
      critical: 'Critical',
    };
    return labels[level] ?? level;
  };

  const getScoreColor = (level: string) => {
    const colors: Record<string, string> = {
      excellent: '#22c55e',
      good: '#06b6d4',
      medium: '#eab308',
      high: '#f97316',
      critical: '#ef4444',
    };
    return colors[level] ?? '#6b7280';
  };

  const level = getScoreLevel(score);
  const color = getScoreColor(level);
  const label = getScoreLabel(level);

  const sizeConfig = {
    sm: { diameter: 80, stroke: 6, fontSize: 'text-lg', labelSize: 'text-xs' },
    md: { diameter: 120, stroke: 8, fontSize: 'text-3xl', labelSize: 'text-sm' },
    lg: { diameter: 160, stroke: 10, fontSize: 'text-4xl', labelSize: 'text-base' },
  };

  const { diameter, stroke, fontSize, labelSize } = sizeConfig[size];
  const radius = (diameter - stroke) / 2;
  const circumference = 2 * Math.PI * radius;
  const progress = (score / 1000) * circumference;
  const offset = circumference - progress;

  return (
    <div className="flex flex-col items-center">
      <div className="relative" style={{ width: diameter, height: diameter }}>
        <svg
          width={diameter}
          height={diameter}
          viewBox={`0 0 ${diameter} ${diameter}`}
          className="transform -rotate-90"
        >
          {/* Background circle */}
          <circle
            cx={diameter / 2}
            cy={diameter / 2}
            r={radius}
            fill="none"
            stroke="currentColor"
            strokeWidth={stroke}
            className="text-bg-tertiary"
          />
          {/* Progress circle */}
          <circle
            cx={diameter / 2}
            cy={diameter / 2}
            r={radius}
            fill="none"
            stroke={color}
            strokeWidth={stroke}
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            className="transition-all duration-500 ease-out"
          />
        </svg>
        {/* Score text */}
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={cn('font-bold text-text-primary', fontSize)}>{score}</span>
          <span className="text-text-tertiary text-xs">/1000</span>
        </div>
      </div>
      {showLabel && (
        <div className="mt-2 text-center">
          <span className={cn('font-medium', labelSize)} style={{ color }}>
            {label}
          </span>
          {trend && trend !== 'stable' && (
            <span
              className={cn(
                'ml-2 text-xs',
                trend === 'up' ? 'text-success' : 'text-error'
              )}
            >
              {trend === 'up' ? '↑' : '↓'} trending {trend}
            </span>
          )}
          {scoreRaw !== undefined && scoreRaw !== score && (
            <div className="text-xs text-text-tertiary mt-1" title="Score before triage (all findings counted)">
              Raw: {scoreRaw}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
