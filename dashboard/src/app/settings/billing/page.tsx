'use client';

import { useState, useEffect } from 'react';
import {
  CreditCard,
  Check,
  Download,
  AlertTriangle,
  Loader2,
} from 'lucide-react';
import { formatDate } from '@/lib/utils';
import { billingApi } from '@/lib/api';

interface PlanInfo {
  id: string;
  name: string;
  price: number;
  interval: string;
  features: string[];
}

interface PaymentMethod {
  id: string;
  type: string;
  last4: string;
  expMonth: number;
  expYear: number;
  isDefault: boolean;
}

interface Invoice {
  id: string;
  date: string;
  description: string;
  amount: number;
  status: 'paid' | 'pending' | 'failed';
  pdfUrl?: string;
}

interface SubscriptionInfo {
  plan: PlanInfo;
  status: 'active' | 'past_due' | 'canceled' | 'trialing';
  currentPeriodStart: string;
  currentPeriodEnd: string;
  cancelAtPeriodEnd: boolean;
}

export default function BillingSettingsPage() {
  const [subscription, setSubscription] = useState<SubscriptionInfo | null>(null);
  const [paymentMethods, setPaymentMethods] = useState<PaymentMethod[]>([]);
  const [invoices, setInvoices] = useState<Invoice[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [cancelModalOpen, setCancelModalOpen] = useState(false);
  const [canceling, setCanceling] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadBillingData();
  }, []);

  async function loadBillingData() {
    try {
      setIsLoading(true);
      setError(null);

      const [billingData, invoicesData] = await Promise.all([
        billingApi.get(),
        billingApi.getInvoices(12),
      ]);

      setSubscription(billingData.subscription);
      setPaymentMethods(billingData.paymentMethods);
      setInvoices(invoicesData);
    } catch (err) {
      console.error('Failed to load billing data:', err);
      setError('Failed to load billing information');
    } finally {
      setIsLoading(false);
    }
  }

  const handleCancelSubscription = async () => {
    setCanceling(true);
    try {
      const result = await billingApi.cancel();
      // Update local state
      if (subscription) {
        setSubscription({
          ...subscription,
          cancelAtPeriodEnd: true,
        });
      }
      setCancelModalOpen(false);
      alert(result.message);
    } catch (err) {
      console.error('Failed to cancel subscription:', err);
      alert(err instanceof Error ? err.message : 'Failed to cancel subscription');
    } finally {
      setCanceling(false);
    }
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

  const currentPlan = subscription?.plan;
  const defaultPaymentMethod = paymentMethods.find(pm => pm.isDefault) || paymentMethods[0];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-lg font-semibold text-text-primary">Billing</h2>
        <p className="text-sm text-text-secondary mt-1">
          Manage your subscription and payment methods.
        </p>
      </div>

      {/* Current Plan */}
      {currentPlan && (
        <div className="bg-bg-secondary border border-border-primary rounded-xl p-6">
          <h3 className="text-sm font-medium text-text-tertiary uppercase tracking-wider mb-4">
            Current Plan
          </h3>
          <div className="flex items-start justify-between">
            <div>
              <div className="flex items-baseline gap-2 mb-3">
                <span className="text-2xl font-bold text-text-primary">{currentPlan.name} Plan</span>
                <span className="text-text-secondary">${currentPlan.price}/{currentPlan.interval}</span>
              </div>
              <ul className="space-y-1 text-sm text-text-secondary mb-4">
                {currentPlan.features.map((feature, i) => (
                  <li key={i} className="flex items-center gap-2">
                    <Check size={14} className="text-success" />
                    {feature}
                  </li>
                ))}
              </ul>
              {subscription && (
                <p className="text-sm text-text-tertiary">
                  {subscription.cancelAtPeriodEnd
                    ? `Subscription ends: ${formatDate(subscription.currentPeriodEnd)}`
                    : `Next billing date: ${formatDate(subscription.currentPeriodEnd)}`}
                </p>
              )}
            </div>
            <div className="flex items-center gap-2">
              <button className="px-4 py-2 text-sm border border-border-primary rounded-lg hover:bg-bg-tertiary transition-colors">
                Change Plan
              </button>
              {!subscription?.cancelAtPeriodEnd && (
                <button
                  onClick={() => setCancelModalOpen(true)}
                  className="px-4 py-2 text-sm text-error border border-error/20 rounded-lg hover:bg-error/10 transition-colors"
                >
                  Cancel Subscription
                </button>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Payment Method */}
      {defaultPaymentMethod && (
        <div className="bg-bg-secondary border border-border-primary rounded-xl p-6">
          <h3 className="text-sm font-medium text-text-tertiary uppercase tracking-wider mb-4">
            Payment Method
          </h3>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="w-12 h-8 bg-bg-tertiary rounded flex items-center justify-center">
                <CreditCard size={20} className="text-text-secondary" />
              </div>
              <div>
                <p className="font-medium text-text-primary">
                  {defaultPaymentMethod.type.charAt(0).toUpperCase() + defaultPaymentMethod.type.slice(1)} ending in {defaultPaymentMethod.last4}
                </p>
                <p className="text-sm text-text-secondary">
                  Expires {defaultPaymentMethod.expMonth}/{defaultPaymentMethod.expYear}
                </p>
              </div>
            </div>
            <button className="px-4 py-2 text-sm border border-border-primary rounded-lg hover:bg-bg-tertiary transition-colors">
              Update Payment Method
            </button>
          </div>
        </div>
      )}

      {/* Billing History */}
      <div className="bg-bg-secondary border border-border-primary rounded-xl overflow-hidden">
        <div className="flex items-center justify-between px-6 py-4 border-b border-border-primary">
          <h3 className="text-sm font-medium text-text-tertiary uppercase tracking-wider">
            Billing History
          </h3>
          <button className="flex items-center gap-2 text-sm text-text-secondary hover:text-text-primary transition-colors">
            <Download size={14} />
            Download All Invoices
          </button>
        </div>
        {invoices.length > 0 ? (
          <table className="w-full">
            <thead>
              <tr className="text-left text-xs text-text-tertiary border-b border-border-primary uppercase tracking-wider">
                <th className="px-6 py-3">Date</th>
                <th className="px-6 py-3">Description</th>
                <th className="px-6 py-3">Amount</th>
                <th className="px-6 py-3">Status</th>
                <th className="px-6 py-3 w-10"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-primary">
              {invoices.map(invoice => (
                <tr key={invoice.id} className="hover:bg-bg-hover/50 transition-colors">
                  <td className="px-6 py-3 text-sm text-text-primary">
                    {formatDate(invoice.date)}
                  </td>
                  <td className="px-6 py-3 text-sm text-text-secondary">
                    {invoice.description}
                  </td>
                  <td className="px-6 py-3 text-sm text-text-primary">
                    ${invoice.amount.toFixed(2)}
                  </td>
                  <td className="px-6 py-3">
                    <span className="flex items-center gap-1 text-sm text-success">
                      <Check size={14} />
                      {invoice.status.charAt(0).toUpperCase() + invoice.status.slice(1)}
                    </span>
                  </td>
                  <td className="px-6 py-3">
                    <button className="p-1 rounded hover:bg-bg-tertiary transition-colors">
                      <Download size={14} className="text-text-tertiary" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div className="p-6 text-center text-text-tertiary">
            No invoices yet
          </div>
        )}
      </div>

      {/* Cancel Subscription Modal */}
      {cancelModalOpen && subscription && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-bg-secondary border border-border-primary rounded-xl w-full max-w-md p-6">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-10 h-10 rounded-full bg-error/10 flex items-center justify-center">
                <AlertTriangle size={20} className="text-error" />
              </div>
              <h2 className="text-lg font-semibold text-text-primary">Cancel Subscription</h2>
            </div>
            <p className="text-sm text-text-secondary mb-4">
              Are you sure you want to cancel your subscription? You'll lose access to:
            </p>
            <ul className="space-y-1 text-sm text-text-secondary mb-6 ml-4">
              <li>- All security scanning tools</li>
              <li>- Access to your projects and findings</li>
              <li>- API access</li>
            </ul>
            <p className="text-sm text-text-tertiary mb-6">
              Your subscription will remain active until {formatDate(subscription.currentPeriodEnd)}.
            </p>
            <div className="flex items-center justify-end gap-3">
              <button
                onClick={() => setCancelModalOpen(false)}
                disabled={canceling}
                className="px-4 py-2 text-sm border border-border-primary rounded-lg hover:bg-bg-tertiary transition-colors"
              >
                Keep Subscription
              </button>
              <button
                onClick={handleCancelSubscription}
                disabled={canceling}
                className="px-4 py-2 text-sm bg-error text-white rounded-lg hover:bg-error/90 transition-colors flex items-center gap-2"
              >
                {canceling ? (
                  <>
                    <Loader2 size={14} className="animate-spin" />
                    Canceling...
                  </>
                ) : (
                  'Cancel Subscription'
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
