'use client';

import { useState, useEffect } from 'react';
import { Mail, MessageSquare, Check, Loader2 } from 'lucide-react';
import { cn } from '@/lib/utils';
import { notificationsApi, authApi } from '@/lib/api';

interface NotificationSetting {
  id: string;
  label: string;
  description: string;
  email: boolean;
  slack: boolean;
}

export default function NotificationsSettingsPage() {
  const [settings, setSettings] = useState<NotificationSetting[]>([]);
  const [slackConnected, setSlackConnected] = useState(false);
  const [slackChannel, setSlackChannel] = useState<string | null>(null);
  const [userEmail, setUserEmail] = useState<string>('');
  const [isLoading, setIsLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadPreferences();
  }, []);

  async function loadPreferences() {
    try {
      setIsLoading(true);
      setError(null);

      // Load preferences and user email in parallel
      const [prefsData, userData] = await Promise.all([
        notificationsApi.getPreferences(),
        authApi.me(),
      ]);

      setSettings(prefsData.settings);
      setSlackConnected(prefsData.slackConnected);
      setSlackChannel(prefsData.slackChannel);
      setUserEmail(userData.user.email);
    } catch (err) {
      console.error('Failed to load preferences:', err);
      setError('Failed to load notification preferences');
    } finally {
      setIsLoading(false);
    }
  }

  const toggleSetting = (id: string, channel: 'email' | 'slack') => {
    setSettings(settings.map(s =>
      s.id === id ? { ...s, [channel]: !s[channel] } : s
    ));
    setSaved(false);
  };

  const handleSave = async () => {
    setSaving(true);
    setError(null);

    try {
      // Only send the fields needed for update
      const settingsToSave = settings.map(s => ({
        id: s.id,
        email: s.email,
        slack: s.slack,
      }));

      await notificationsApi.updatePreferences(settingsToSave);
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    } catch (err) {
      console.error('Failed to save preferences:', err);
      setError(err instanceof Error ? err.message : 'Failed to save preferences');
    } finally {
      setSaving(false);
    }
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <Loader2 className="h-8 w-8 animate-spin text-primary-500" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-lg font-semibold text-text-primary">Notifications</h2>
        <p className="text-sm text-text-secondary mt-1">
          Choose how you want to be notified about security events.
        </p>
      </div>

      {error && (
        <div className="bg-error/10 border border-error/20 rounded-lg p-4 text-sm text-error">
          {error}
        </div>
      )}

      {/* Email Notifications */}
      <div className="bg-bg-secondary border border-border-primary rounded-xl p-6">
        <div className="flex items-center gap-3 mb-6">
          <div className="w-10 h-10 rounded-lg bg-primary-500/10 flex items-center justify-center">
            <Mail size={20} className="text-primary-400" />
          </div>
          <div>
            <h3 className="font-semibold text-text-primary">Email Notifications</h3>
            <p className="text-sm text-text-secondary">Sent to {userEmail || 'your email'}</p>
          </div>
        </div>

        <div className="space-y-4">
          {settings.map(setting => (
            <div key={setting.id} className="flex items-center justify-between py-2">
              <div>
                <p className="text-sm font-medium text-text-primary">{setting.label}</p>
                <p className="text-xs text-text-tertiary">{setting.description}</p>
              </div>
              <button
                onClick={() => toggleSetting(setting.id, 'email')}
                className={cn(
                  'relative w-11 h-6 rounded-full transition-colors',
                  setting.email ? 'bg-primary-500' : 'bg-bg-tertiary'
                )}
              >
                <span
                  className={cn(
                    'absolute top-1 w-4 h-4 bg-white rounded-full transition-transform',
                    setting.email ? 'left-6' : 'left-1'
                  )}
                />
              </button>
            </div>
          ))}
        </div>
      </div>

      {/* Slack Notifications */}
      <div className="bg-bg-secondary border border-border-primary rounded-xl p-6">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-[#4A154B]/10 flex items-center justify-center">
              <MessageSquare size={20} className="text-[#E01E5A]" />
            </div>
            <div>
              <h3 className="font-semibold text-text-primary">Slack Notifications</h3>
              {slackConnected ? (
                <p className="text-sm text-text-secondary">Connected to {slackChannel || '#notifications'}</p>
              ) : (
                <p className="text-sm text-text-tertiary">Not connected</p>
              )}
            </div>
          </div>
          {!slackConnected && (
            <button className="px-4 py-2 text-sm bg-primary-500 text-white rounded-lg hover:bg-primary-600 transition-colors">
              Connect Slack
            </button>
          )}
        </div>

        {slackConnected ? (
          <div className="space-y-4">
            {settings.map(setting => (
              <div key={setting.id} className="flex items-center justify-between py-2">
                <div>
                  <p className="text-sm font-medium text-text-primary">{setting.label}</p>
                  <p className="text-xs text-text-tertiary">{setting.description}</p>
                </div>
                <button
                  onClick={() => toggleSetting(setting.id, 'slack')}
                  className={cn(
                    'relative w-11 h-6 rounded-full transition-colors',
                    setting.slack ? 'bg-primary-500' : 'bg-bg-tertiary'
                  )}
                >
                  <span
                    className={cn(
                      'absolute top-1 w-4 h-4 bg-white rounded-full transition-transform',
                      setting.slack ? 'left-6' : 'left-1'
                    )}
                  />
                </button>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-center py-8 text-text-tertiary">
            Connect Slack to enable notifications
          </div>
        )}
      </div>

      {/* Save Button */}
      <div className="flex items-center justify-end gap-3">
        {saved && (
          <span className="flex items-center gap-1 text-sm text-success">
            <Check size={14} />
            Preferences saved
          </span>
        )}
        <button
          onClick={handleSave}
          disabled={saving}
          className="px-4 py-2 text-sm bg-primary-500 text-white rounded-lg hover:bg-primary-600 disabled:opacity-50 transition-colors flex items-center gap-2"
        >
          {saving ? (
            <>
              <Loader2 size={14} className="animate-spin" />
              Saving...
            </>
          ) : (
            'Save Preferences'
          )}
        </button>
      </div>
    </div>
  );
}
