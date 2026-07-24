import Link from 'next/link';
import { Shield } from 'lucide-react';

interface LogoProps {
  size?: 'sm' | 'md' | 'lg';
  showText?: boolean;
}

export function Logo({ size = 'md', showText = true }: LogoProps) {
  const iconSizes = {
    sm: 'h-5 w-5',
    md: 'h-6 w-6',
    lg: 'h-8 w-8',
  };

  const textSizes = {
    sm: 'text-base',
    md: 'text-lg',
    lg: 'text-xl',
  };

  return (
    <Link href="/" className="flex items-center gap-2 hover:opacity-90 transition-opacity">
      <div className="relative">
        <div className="absolute inset-0 bg-gradient-to-br from-primary-500 to-accent-500 rounded-lg blur-sm opacity-50" />
        <div className="relative bg-gradient-to-br from-primary-500 to-accent-500 p-1.5 rounded-lg">
          <Shield className={`${iconSizes[size]} text-white`} aria-hidden="true" />
        </div>
      </div>
      {showText && (
        <span className={`font-semibold text-text-primary ${textSizes[size]}`}>
          Code Hardener
        </span>
      )}
    </Link>
  );
}
