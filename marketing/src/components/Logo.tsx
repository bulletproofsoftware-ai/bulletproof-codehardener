'use client';

import { cn } from '@/lib/utils';

interface LogoProps {
  className?: string;
  showText?: boolean;
}

export function Logo({ className, showText = true }: LogoProps) {
  return (
    <div className="flex items-center gap-2">
      <svg
        viewBox="0 0 32 32"
        className={cn('h-8 w-8', className)}
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        aria-hidden="true"
      >
        {/* Shield shape with gradient */}
        <path
          d="M16 2L4 8v8c0 7.18 5.12 13.88 12 16 6.88-2.12 12-8.82 12-16V8L16 2z"
          fill="url(#logo-gradient)"
        />
        {/* Checkmark inside */}
        <path
          d="M12 16l3 3 5-6"
          stroke="white"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
        {/* AI dot accent */}
        <circle cx="22" cy="10" r="2" fill="white" opacity="0.8" />
        <defs>
          <linearGradient id="logo-gradient" x1="4" y1="2" x2="28" y2="26">
            <stop stopColor="#06b6d4" />
            <stop offset="1" stopColor="#8b5cf6" />
          </linearGradient>
        </defs>
      </svg>
      {showText && (
        <span className="font-semibold text-lg text-text-primary">
          Code Hardener
        </span>
      )}
    </div>
  );
}
