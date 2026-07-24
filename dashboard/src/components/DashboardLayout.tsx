'use client';

import { usePathname, useRouter } from 'next/navigation';
import { useEffect, useState } from 'react';
import { useAuth } from '@/contexts/AuthContext';
import { Sidebar } from '@/components/Sidebar';
import { Header } from '@/components/Header';
import { Loader2 } from 'lucide-react';

const publicRoutes = ['/login'];

export function DashboardLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const { isAuthenticated, isLoading } = useAuth();

  // Track client-side mount state
  const [mounted, setMounted] = useState(false);

  const isPublicRoute = publicRoutes.includes(pathname);

  // Mark as mounted after hydration
  useEffect(() => {
    setMounted(true);
  }, []);

  // Check dev mode directly (only valid after mount)
  const isDevMode = mounted && (
    process.env.NEXT_PUBLIC_DEV_MODE === 'true' ||
    window.location.hostname === 'localhost'
  );

  // Handle auth redirects - only in production mode
  useEffect(() => {
    // Skip until mounted
    if (!mounted) return;

    // In dev mode (localhost), skip all redirect logic
    if (process.env.NEXT_PUBLIC_DEV_MODE === 'true' || window.location.hostname === 'localhost') {
      console.log('[DashboardLayout] DEV_MODE - skipping redirects');
      return;
    }

    console.log('[DashboardLayout] Auth state:', { isLoading, isAuthenticated, pathname, isPublicRoute });
    if (!isLoading) {
      if (!isAuthenticated && !isPublicRoute) {
        console.log('[DashboardLayout] Redirecting to /login');
        router.replace('/login');
      }
      if (isAuthenticated && pathname === '/login') {
        console.log('[DashboardLayout] Redirecting to /');
        router.replace('/');
      }
    }
  }, [mounted, isAuthenticated, isLoading, isPublicRoute, pathname, router]);

  // During SSR, show loading
  if (!mounted) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <Loader2 className="h-8 w-8 animate-spin text-blue-600" />
          <p className="text-sm text-gray-500">Loading...</p>
        </div>
      </div>
    );
  }

  // DEV MODE: Always show dashboard (no auth checks)
  if (isDevMode) {
    if (isPublicRoute) {
      return <>{children}</>;
    }
    return (
      <div className="flex h-screen overflow-hidden">
        <Sidebar />
        <div className="flex-1 flex flex-col overflow-hidden">
          <Header />
          <main id="main-content" className="flex-1 overflow-y-auto p-6" role="main">
            {children}
          </main>
        </div>
      </div>
    );
  }

  // PRODUCTION: Normal auth flow
  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <Loader2 className="h-8 w-8 animate-spin text-blue-600" />
          <p className="text-sm text-gray-500">Loading...</p>
        </div>
      </div>
    );
  }

  if (isPublicRoute) {
    return <>{children}</>;
  }

  if (!isAuthenticated) {
    return null;
  }

  // Authenticated users see the full dashboard layout
  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden">
        <Header />
        <main
          id="main-content"
          className="flex-1 overflow-y-auto p-6"
          role="main"
        >
          {children}
        </main>
      </div>
    </div>
  );
}
