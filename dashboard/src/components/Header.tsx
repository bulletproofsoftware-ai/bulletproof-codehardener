'use client';

import { useState, useRef, useEffect, useCallback } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import {
  Bell,
  Search,
  Plus,
  User,
  Settings,
  LogOut,
  HelpCircle,
  ExternalLink,
  Loader2,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { notificationsApi, authApi } from '@/lib/api';

interface Notification {
  id: string;
  type: 'info' | 'warning' | 'error' | 'success';
  title: string;
  message: string;
  createdAt: string;
  read: boolean;
}

interface UserData {
  id: string;
  name?: string;
  email: string;
  avatar?: string;
}

// Dev mode mock user
const DEV_USER: UserData = {
  id: 'dev-user-001',
  email: 'dev@codehardener.local',
  name: 'Developer',
};

function getInitials(name: string): string {
  return name
    .split(' ')
    .map((n) => n[0])
    .join('')
    .toUpperCase()
    .slice(0, 2);
}

function formatTimeAgo(dateString: string): string {
  const date = new Date(dateString);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays = Math.floor(diffMs / 86400000);

  if (diffMins < 1) return 'just now';
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  return `${diffDays}d ago`;
}

export function Header() {
  const router = useRouter();
  const [showNotifications, setShowNotifications] = useState(false);
  const [showUserMenu, setShowUserMenu] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const notificationRef = useRef<HTMLDivElement>(null);
  const userMenuRef = useRef<HTMLDivElement>(null);

  // Real data state
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [notificationsLoading, setNotificationsLoading] = useState(false);
  const [user, setUser] = useState<UserData | null>(null);
  const [userLoading, setUserLoading] = useState(true);

  // Fetch user data on mount
  useEffect(() => {
    // In dev mode, use mock user
    const isDevMode = process.env.NEXT_PUBLIC_DEV_MODE === 'true' ||
      window.location.hostname === 'localhost';

    if (isDevMode) {
      setUser(DEV_USER);
      setUserLoading(false);
      return;
    }

    async function fetchUser() {
      try {
        const userData = await authApi.me();
        setUser(userData.user);
      } catch (error) {
        console.error('Failed to fetch user:', error);
        // If auth fails, redirect to login
        router.push('/login');
      } finally {
        setUserLoading(false);
      }
    }
    fetchUser();
  }, [router]);

  // Fetch notifications when dropdown opens
  const fetchNotifications = useCallback(async () => {
    if (notificationsLoading) return;
    setNotificationsLoading(true);
    try {
      const data = await notificationsApi.list();
      setNotifications(data || []);
    } catch (error) {
      console.error('Failed to fetch notifications:', error);
    } finally {
      setNotificationsLoading(false);
    }
  }, [notificationsLoading]);

  // Fetch notifications when dropdown opens
  useEffect(() => {
    if (showNotifications) {
      fetchNotifications();
    }
  }, [showNotifications, fetchNotifications]);

  const unreadCount = notifications.filter((n) => !n.read).length;

  // Mark all notifications as read
  const handleMarkAllRead = async () => {
    try {
      await notificationsApi.markAllRead();
      setNotifications((prev) => prev.map((n) => ({ ...n, read: true })));
    } catch (error) {
      console.error('Failed to mark all as read:', error);
    }
  };

  // Mark single notification as read
  const handleNotificationClick = async (id: string) => {
    try {
      await notificationsApi.markRead(id);
      setNotifications((prev) =>
        prev.map((n) => (n.id === id ? { ...n, read: true } : n))
      );
    } catch (error) {
      console.error('Failed to mark notification as read:', error);
    }
  };

  // Handle sign out
  const handleSignOut = async () => {
    try {
      await authApi.logout();
      router.push('/login');
    } catch (error) {
      console.error('Failed to sign out:', error);
      // Force redirect anyway
      router.push('/login');
    }
  };

  // Close notifications dropdown on Escape
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setShowNotifications(false);
      }
    };
    if (showNotifications) {
      document.addEventListener('keydown', handleKeyDown);
      return () => document.removeEventListener('keydown', handleKeyDown);
    }
  }, [showNotifications]);

  // Close user menu on Escape
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setShowUserMenu(false);
      }
    };
    if (showUserMenu) {
      document.addEventListener('keydown', handleKeyDown);
      return () => document.removeEventListener('keydown', handleKeyDown);
    }
  }, [showUserMenu]);

  // Close dropdowns on outside click
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (
        notificationRef.current &&
        !notificationRef.current.contains(event.target as Node)
      ) {
        setShowNotifications(false);
      }
      if (
        userMenuRef.current &&
        !userMenuRef.current.contains(event.target as Node)
      ) {
        setShowUserMenu(false);
      }
    }

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  return (
    <header className="h-16 border-b border-border-primary bg-bg-secondary flex items-center justify-between px-6">
      {/* Search */}
      <div className="relative w-96">
        <Search
          className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-text-tertiary"
          aria-hidden="true"
        />
        <input
          type="search"
          placeholder="Search projects, scans, findings..."
          className="input pl-10 py-2 text-sm"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          aria-label="Search"
        />
      </div>

      {/* Right side actions */}
      <div className="flex items-center gap-2">
        {/* New Scan Button */}
        <Link
          href="/scans/new"
          className="btn-primary btn-sm hidden sm:inline-flex"
        >
          <Plus className="h-4 w-4" aria-hidden="true" />
          New Scan
        </Link>

        {/* Help */}
        <a
          href={`${process.env.NEXT_PUBLIC_MARKETING_URL || 'http://localhost:3000'}/docs`}
          target="_blank"
          rel="noopener noreferrer"
          className="btn-icon text-text-tertiary hover:text-text-secondary"
          aria-label="Help and documentation"
        >
          <HelpCircle className="h-5 w-5" aria-hidden="true" />
        </a>

        {/* Notifications */}
        <div className="relative" ref={notificationRef}>
          <button
            onClick={() => setShowNotifications(!showNotifications)}
            className="btn-icon text-text-tertiary hover:text-text-secondary relative"
            aria-label={`Notifications${unreadCount > 0 ? `, ${unreadCount} unread` : ''}`}
            aria-expanded={showNotifications}
          >
            <Bell className="h-5 w-5" aria-hidden="true" />
            {unreadCount > 0 && (
              <span className="absolute -top-0.5 -right-0.5 h-4 w-4 bg-error text-white text-xs font-medium rounded-full flex items-center justify-center">
                {unreadCount}
              </span>
            )}
          </button>

          {showNotifications && (
            <div className="absolute right-0 mt-2 w-80 dropdown-menu z-50 animate-fade-in">
              <div className="flex items-center justify-between px-4 py-3 border-b border-border-primary">
                <h3 className="font-medium text-text-primary">Notifications</h3>
                {unreadCount > 0 && (
                  <button
                    onClick={handleMarkAllRead}
                    className="text-xs text-primary-500 hover:underline"
                  >
                    Mark all read
                  </button>
                )}
              </div>
              <div className="max-h-80 overflow-y-auto">
                {notificationsLoading ? (
                  <div className="px-4 py-8 flex items-center justify-center">
                    <Loader2 className="h-5 w-5 animate-spin text-text-tertiary" />
                  </div>
                ) : notifications.length > 0 ? (
                  notifications.map((notification) => (
                    <div
                      key={notification.id}
                      onClick={() => handleNotificationClick(notification.id)}
                      className={cn(
                        'px-4 py-3 border-b border-border-primary last:border-0 hover:bg-bg-hover cursor-pointer',
                        !notification.read && 'bg-primary-500/5'
                      )}
                    >
                      <p className="text-sm text-text-primary">
                        {notification.message}
                      </p>
                      <p className="text-xs text-text-tertiary mt-1">
                        {formatTimeAgo(notification.createdAt)}
                      </p>
                    </div>
                  ))
                ) : (
                  <div className="px-4 py-8 text-center text-text-tertiary text-sm">
                    No notifications
                  </div>
                )}
              </div>
              <div className="border-t border-border-primary px-4 py-2">
                <Link
                  href="/settings/notifications"
                  className="text-xs text-text-secondary hover:text-text-primary flex items-center gap-1"
                >
                  Notification settings
                  <ExternalLink className="h-3 w-3" aria-hidden="true" />
                </Link>
              </div>
            </div>
          )}
        </div>

        {/* User menu */}
        <div className="relative" ref={userMenuRef}>
          <button
            onClick={() => setShowUserMenu(!showUserMenu)}
            className="flex items-center gap-2 p-1.5 rounded-md hover:bg-bg-hover transition-colors"
            aria-label="User menu"
            aria-expanded={showUserMenu}
          >
            <div className="h-8 w-8 rounded-full bg-gradient-to-br from-primary-500 to-accent-500 flex items-center justify-center">
              {userLoading ? (
                <Loader2 className="h-4 w-4 animate-spin text-white" />
              ) : user?.avatar ? (
                <img
                  src={user.avatar}
                  alt={user.name}
                  className="h-8 w-8 rounded-full object-cover"
                />
              ) : (
                <span className="text-sm font-medium text-white">
                  {user ? getInitials(user.name || user.email) : '??'}
                </span>
              )}
            </div>
          </button>

          {showUserMenu && (
            <div className="absolute right-0 mt-2 w-56 dropdown-menu z-50 animate-fade-in">
              <div className="px-4 py-3 border-b border-border-primary">
                {userLoading ? (
                  <div className="flex items-center gap-2">
                    <Loader2 className="h-4 w-4 animate-spin text-text-tertiary" />
                    <span className="text-sm text-text-tertiary">Loading...</span>
                  </div>
                ) : user ? (
                  <>
                    <p className="font-medium text-text-primary">{user.name}</p>
                    <p className="text-sm text-text-tertiary">{user.email}</p>
                  </>
                ) : (
                  <p className="text-sm text-text-tertiary">Not signed in</p>
                )}
              </div>
              <div className="py-1">
                <Link href="/settings" className="dropdown-item">
                  <User className="h-4 w-4" aria-hidden="true" />
                  Profile
                </Link>
                <Link href="/settings" className="dropdown-item">
                  <Settings className="h-4 w-4" aria-hidden="true" />
                  Settings
                </Link>
              </div>
              <div className="border-t border-border-primary py-1">
                <button
                  onClick={handleSignOut}
                  className="dropdown-item-danger w-full text-left"
                >
                  <LogOut className="h-4 w-4" aria-hidden="true" />
                  Sign out
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
