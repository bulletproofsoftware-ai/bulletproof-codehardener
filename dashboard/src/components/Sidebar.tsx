'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  LayoutDashboard,
  FolderKanban,
  ScanSearch,
  AlertTriangle,
  BadgeCheck,
  FileText,
  Settings,
  Shield,
  ChevronLeft,
  ChevronRight,
  Sun,
  Moon,
  TestTube2,
} from 'lucide-react';
import { useState, useEffect } from 'react';
import { cn } from '@/lib/utils';
import { Logo } from './Logo';
import { useTheme } from '@/contexts/ThemeContext';
import { findingsApi } from '@/lib/api';

interface NavItem {
  label: string;
  href: string;
  icon: React.ElementType;
  badge?: number;
}

const baseNavItems: NavItem[] = [
  { label: 'Overview', href: '/', icon: LayoutDashboard },
  { label: 'Projects', href: '/projects', icon: FolderKanban },
  { label: 'Scans', href: '/scans', icon: ScanSearch },
  { label: 'Findings', href: '/findings', icon: AlertTriangle },
  { label: 'Attestations', href: '/attestations', icon: BadgeCheck },
  { label: 'Reports', href: '/reports', icon: FileText },
  { label: 'Tests', href: '/tests', icon: TestTube2 },
];

const bottomNavItems: NavItem[] = [
  { label: 'Policies', href: '/policies', icon: Shield },
  { label: 'Settings', href: '/settings', icon: Settings },
];

export function Sidebar() {
  const pathname = usePathname();
  const [collapsed, setCollapsed] = useState(false);
  const [findingsCount, setFindingsCount] = useState<number>(0);
  const { theme, toggleTheme } = useTheme();

  useEffect(() => {
    findingsApi.list({ limit: 1, statuses: ['open'] })
      .then((res) => {
        const total = res?.summary?.total ?? res?.pagination?.total ?? 0;
        setFindingsCount(total);
      })
      .catch(() => setFindingsCount(0));
  }, [pathname]);

  const mainNavItems = baseNavItems.map((item) =>
    item.label === 'Findings' ? { ...item, badge: findingsCount } : item
  );

  const isActive = (href: string) => {
    if (href === '/') return pathname === '/';
    return pathname.startsWith(href);
  };

  return (
    <aside
      className={cn(
        'flex flex-col bg-bg-secondary border-r border-border-primary transition-all duration-200',
        collapsed ? 'w-16' : 'w-64'
      )}
      role="navigation"
      aria-label="Main navigation"
    >
      {/* Logo */}
      <div className={cn(
        'flex items-center h-16 px-4 border-b border-border-primary',
        collapsed ? 'justify-center' : 'justify-between'
      )}>
        {!collapsed && <Logo />}
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="p-1.5 rounded-md text-text-tertiary hover:text-text-secondary hover:bg-bg-hover transition-colors"
          aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          {collapsed ? (
            <ChevronRight className="h-4 w-4" aria-hidden="true" />
          ) : (
            <ChevronLeft className="h-4 w-4" aria-hidden="true" />
          )}
        </button>
      </div>

      {/* Main navigation */}
      <nav className="flex-1 py-4 overflow-y-auto">
        <ul className="space-y-1 px-2" role="list">
          {mainNavItems.map((item) => (
            <li key={item.href}>
              <Link
                href={item.href}
                className={cn(
                  'flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-colors',
                  isActive(item.href)
                    ? 'bg-primary-500/10 text-primary-500'
                    : 'text-text-secondary hover:text-text-primary hover:bg-bg-hover',
                  collapsed && 'justify-center px-2'
                )}
                aria-current={isActive(item.href) ? 'page' : undefined}
                title={collapsed ? item.label : undefined}
              >
                <item.icon className="h-5 w-5 flex-shrink-0" aria-hidden="true" />
                {!collapsed && (
                  <>
                    <span className="flex-1">{item.label}</span>
                    {item.badge !== undefined && item.badge > 0 && (
                      <span className="bg-error/10 text-error text-xs font-medium px-2 py-0.5 rounded-full">
                        {item.badge}
                      </span>
                    )}
                  </>
                )}
              </Link>
            </li>
          ))}
        </ul>
      </nav>

      {/* Bottom navigation */}
      <div className="py-4 border-t border-border-primary">
        <ul className="space-y-1 px-2" role="list">
          {/* Theme Toggle */}
          <li>
            <button
              onClick={toggleTheme}
              className={cn(
                'flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-colors w-full',
                'text-text-secondary hover:text-text-primary hover:bg-bg-hover',
                collapsed && 'justify-center px-2'
              )}
              title={collapsed ? (theme === 'light' ? 'Dark mode' : 'Light mode') : undefined}
              aria-label={theme === 'light' ? 'Switch to dark mode' : 'Switch to light mode'}
            >
              {theme === 'light' ? (
                <Moon className="h-5 w-5 flex-shrink-0" aria-hidden="true" />
              ) : (
                <Sun className="h-5 w-5 flex-shrink-0" aria-hidden="true" />
              )}
              {!collapsed && <span>{theme === 'light' ? 'Dark mode' : 'Light mode'}</span>}
            </button>
          </li>
          {bottomNavItems.map((item) => (
            <li key={item.href}>
              <Link
                href={item.href}
                className={cn(
                  'flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-colors',
                  isActive(item.href)
                    ? 'bg-primary-500/10 text-primary-500'
                    : 'text-text-secondary hover:text-text-primary hover:bg-bg-hover',
                  collapsed && 'justify-center px-2'
                )}
                aria-current={isActive(item.href) ? 'page' : undefined}
                title={collapsed ? item.label : undefined}
              >
                <item.icon className="h-5 w-5 flex-shrink-0" aria-hidden="true" />
                {!collapsed && <span>{item.label}</span>}
              </Link>
            </li>
          ))}
        </ul>
      </div>
    </aside>
  );
}
