'use client';

import { useState, useEffect } from 'react';
import {
  Github,
  GitlabIcon,
  MessageSquare,
  Webhook,
  Check,
  ExternalLink,
  Settings,
  Unplug,
  Loader2,
  Ticket,
  LineChart,
} from 'lucide-react';
import { integrationsApi } from '@/lib/api';

interface Integration {
  id: string;
  provider: string;
  name: string;
  description: string;
  connected: boolean;
  connectedAt?: string;
  details?: string;
}

const INTEGRATION_ICONS: Record<string, React.ElementType> = {
  github: Github,
  gitlab: GitlabIcon,
  slack: MessageSquare,
  webhooks: Webhook,
  jira: Ticket,
  linear: LineChart,
};

export default function IntegrationsSettingsPage() {
  const [integrations, setIntegrations] = useState<Integration[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [connectingId, setConnectingId] = useState<string | null>(null);
  const [disconnectingId, setDisconnectingId] = useState<string | null>(null);

  useEffect(() => {
    loadIntegrations();
  }, []);

  async function loadIntegrations() {
    try {
      setIsLoading(true);
      setError(null);
      const data = await integrationsApi.list();
      setIntegrations(data);
    } catch (err) {
      console.error('Failed to load integrations:', err);
      setError('Failed to load integrations');
    } finally {
      setIsLoading(false);
    }
  }

  const handleConnect = async (provider: string) => {
    setConnectingId(provider);
    try {
      const result = await integrationsApi.connect(provider);

      // If OAuth flow is required, redirect to OAuth URL
      if (result.oauthUrl) {
        window.location.href = result.oauthUrl;
        return;
      }

      // Reload integrations to show connected status
      await loadIntegrations();
    } catch (err) {
      console.error('Failed to connect integration:', err);
      alert(err instanceof Error ? err.message : 'Failed to connect integration');
    } finally {
      setConnectingId(null);
    }
  };

  const handleDisconnect = async (provider: string) => {
    if (!confirm(`Are you sure you want to disconnect this integration?`)) {
      return;
    }

    setDisconnectingId(provider);
    try {
      await integrationsApi.disconnect(provider);
      // Update local state
      setIntegrations(integrations.map(item =>
        item.provider === provider ? { ...item, connected: false, details: undefined } : item
      ));
    } catch (err) {
      console.error('Failed to disconnect integration:', err);
      alert(err instanceof Error ? err.message : 'Failed to disconnect integration');
    } finally {
      setDisconnectingId(null);
    }
  };

  const handleManage = (provider: string) => {
    // For now, just log - in production this would open a settings modal
    console.log('Manage integration:', provider);
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <Loader2 className="h-8 w-8 animate-spin text-primary-500" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-error/10 border border-error/20 rounded-lg p-4 text-sm text-error">
        {error}
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-lg font-semibold text-text-primary">Integrations</h2>
        <p className="text-sm text-text-secondary mt-1">
          Connect Code Hardener to your development tools.
        </p>
      </div>

      {/* Integrations List */}
      <div className="space-y-4">
        {integrations.map(integration => (
          <IntegrationCard
            key={integration.provider}
            integration={integration}
            icon={INTEGRATION_ICONS[integration.provider] || Webhook}
            isConnecting={connectingId === integration.provider}
            isDisconnecting={disconnectingId === integration.provider}
            onConnect={() => handleConnect(integration.provider)}
            onDisconnect={() => handleDisconnect(integration.provider)}
            onManage={() => handleManage(integration.provider)}
          />
        ))}
      </div>
    </div>
  );
}

function IntegrationCard({
  integration,
  icon: Icon,
  isConnecting,
  isDisconnecting,
  onConnect,
  onDisconnect,
  onManage,
}: {
  integration: Integration;
  icon: React.ElementType;
  isConnecting: boolean;
  isDisconnecting: boolean;
  onConnect: () => void;
  onDisconnect: () => void;
  onManage: () => void;
}) {
  return (
    <div className="bg-bg-secondary border border-border-primary rounded-xl p-6">
      <div className="flex items-start justify-between">
        <div className="flex items-start gap-4">
          <div className="w-12 h-12 rounded-lg bg-bg-tertiary flex items-center justify-center">
            <Icon size={24} className="text-text-primary" />
          </div>
          <div>
            <h3 className="font-semibold text-text-primary">{integration.name}</h3>
            <p className="text-sm text-text-secondary mt-1">{integration.description}</p>
            {integration.connected && (
              <div className="flex items-center gap-2 mt-2">
                <Check size={14} className="text-success" />
                <span className="text-sm text-success">Connected</span>
                {integration.details && (
                  <span className="text-sm text-text-tertiary">({integration.details})</span>
                )}
              </div>
            )}
          </div>
        </div>
        <div className="flex items-center gap-2">
          {integration.connected ? (
            <>
              <button
                onClick={onManage}
                disabled={isDisconnecting}
                className="flex items-center gap-2 px-3 py-1.5 text-sm border border-border-primary rounded-lg hover:bg-bg-tertiary transition-colors disabled:opacity-50"
              >
                <Settings size={14} />
                Manage
              </button>
              <button
                onClick={onDisconnect}
                disabled={isDisconnecting}
                className="flex items-center gap-2 px-3 py-1.5 text-sm border border-error/20 text-error rounded-lg hover:bg-error/10 transition-colors disabled:opacity-50"
              >
                {isDisconnecting ? (
                  <Loader2 size={14} className="animate-spin" />
                ) : (
                  <Unplug size={14} />
                )}
                {isDisconnecting ? 'Disconnecting...' : 'Disconnect'}
              </button>
            </>
          ) : (
            <button
              onClick={onConnect}
              disabled={isConnecting}
              className="flex items-center gap-2 px-4 py-2 text-sm bg-primary-500 text-white rounded-lg hover:bg-primary-600 transition-colors disabled:opacity-50"
            >
              {isConnecting ? (
                <Loader2 size={14} className="animate-spin" />
              ) : (
                <ExternalLink size={14} />
              )}
              {isConnecting ? 'Connecting...' : `Connect ${integration.name}`}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
