'use client';

import { useState, useEffect } from 'react';
import {
  Users,
  Plus,
  MoreVertical,
  Mail,
  Trash2,
  Shield,
  Crown,
  User,
  X,
  AlertCircle,
  Loader2,
} from 'lucide-react';
import { cn, formatDate } from '@/lib/utils';
import { EmptyState } from '@/components/EmptyState';
import { teamApi } from '@/lib/api';
import type { TeamMember } from '@/types';

const roleConfig = {
  owner: { label: 'Owner', icon: Crown, color: 'text-warning' },
  admin: { label: 'Admin', icon: Shield, color: 'text-primary-400' },
  member: { label: 'Member', icon: User, color: 'text-text-secondary' },
  viewer: { label: 'Viewer', icon: User, color: 'text-text-tertiary' },
};

export default function TeamSettingsPage() {
  const [members, setMembers] = useState<TeamMember[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [inviteModalOpen, setInviteModalOpen] = useState(false);
  const [menuOpen, setMenuOpen] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState<string | null>(null);

  useEffect(() => {
    fetchTeamMembers();
  }, []);

  async function fetchTeamMembers() {
    try {
      setIsLoading(true);
      setError(null);
      const data = await teamApi.list();
      setMembers(data);
    } catch (err) {
      console.error('Failed to fetch team members:', err);
      setError(err instanceof Error ? err.message : 'Failed to load team members');
    } finally {
      setIsLoading(false);
    }
  }

  const handleInvite = async (email: string, role: 'admin' | 'member' | 'viewer') => {
    try {
      setActionLoading('invite');
      const newMember = await teamApi.invite(email, role);
      setMembers([...members, newMember]);
      setInviteModalOpen(false);
    } catch (err) {
      console.error('Failed to invite member:', err);
      alert(err instanceof Error ? err.message : 'Failed to invite member');
    } finally {
      setActionLoading(null);
    }
  };

  const handleRemove = async (id: string) => {
    if (!confirm('Are you sure you want to remove this team member?')) {
      return;
    }
    try {
      setActionLoading(id);
      await teamApi.remove(id);
      setMembers(members.filter(m => m.id !== id));
      setMenuOpen(null);
    } catch (err) {
      console.error('Failed to remove member:', err);
      alert(err instanceof Error ? err.message : 'Failed to remove member');
    } finally {
      setActionLoading(null);
    }
  };

  const handleChangeRole = async (id: string, role: 'admin' | 'member' | 'viewer') => {
    try {
      setActionLoading(id);
      await teamApi.updateRole(id, role);
      setMembers(members.map(m =>
        m.id === id ? { ...m, role } : m
      ));
      setMenuOpen(null);
    } catch (err) {
      console.error('Failed to change role:', err);
      alert(err instanceof Error ? err.message : 'Failed to change role');
    } finally {
      setActionLoading(null);
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
      <div className="flex flex-col items-center justify-center min-h-[400px] text-center">
        <AlertCircle className="h-12 w-12 text-error mb-4" />
        <h2 className="text-xl font-semibold text-text-primary mb-2">Failed to load team</h2>
        <p className="text-text-secondary mb-4">{error}</p>
        <button
          onClick={fetchTeamMembers}
          className="px-4 py-2 bg-primary-500 text-white rounded-lg hover:bg-primary-600 transition-colors"
        >
          Try Again
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-text-primary">Team</h2>
          <p className="text-sm text-text-secondary mt-1">
            Manage team members and their permissions.
          </p>
        </div>
        <button
          onClick={() => setInviteModalOpen(true)}
          className="flex items-center gap-2 px-4 py-2 text-sm bg-primary-500 text-white rounded-lg hover:bg-primary-600 transition-colors"
        >
          <Plus size={16} />
          Invite Member
        </button>
      </div>

      {/* Team Members Table */}
      {members.length === 0 ? (
        <EmptyState
          icon={Users}
          title="No team members yet"
          description="Invite your first team member to collaborate on security scans."
          action={{ label: 'Invite Member', onClick: () => setInviteModalOpen(true) }}
        />
      ) : (
        <div className="bg-bg-secondary border border-border-primary rounded-xl overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="text-left text-xs text-text-tertiary border-b border-border-primary uppercase tracking-wider">
                <th className="px-4 py-3">Member</th>
                <th className="px-4 py-3">Email</th>
                <th className="px-4 py-3">Role</th>
                <th className="px-4 py-3">Joined</th>
                <th className="px-4 py-3 w-10"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-primary">
              {members.map(member => {
                const roleInfo = roleConfig[member.role];
                const RoleIcon = roleInfo.icon;
                const isPending = member.status === 'pending';
                const memberName = member.name || (member.firstName && member.lastName
                  ? `${member.firstName} ${member.lastName}`
                  : member.firstName || null);

                return (
                  <tr key={member.id} className="hover:bg-bg-hover/50 transition-colors">
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-3">
                        <div className="w-8 h-8 rounded-full bg-bg-tertiary flex items-center justify-center">
                          {memberName ? (
                            <span className="text-sm font-medium text-text-primary">
                              {memberName.split(' ').map(n => n[0]).join('')}
                            </span>
                          ) : (
                            <User size={14} className="text-text-tertiary" />
                          )}
                        </div>
                        <div>
                          <span className={cn('font-medium', isPending ? 'text-text-tertiary' : 'text-text-primary')}>
                            {memberName || '(pending)'}
                          </span>
                          {isPending && (
                            <span className="ml-2 text-xs text-warning bg-warning/10 px-1.5 py-0.5 rounded">
                              Pending
                            </span>
                          )}
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-sm text-text-secondary">
                      {member.email}
                    </td>
                    <td className="px-4 py-3">
                      <div className={cn('flex items-center gap-2 text-sm', roleInfo.color)}>
                        <RoleIcon size={14} />
                        {roleInfo.label}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-sm text-text-secondary">
                      {formatDate(member.joinedAt)}
                    </td>
                    <td className="px-4 py-3">
                      {member.role !== 'owner' && (
                        <div className="relative">
                          <button
                            onClick={() => setMenuOpen(menuOpen === member.id ? null : member.id)}
                            className="p-1 rounded hover:bg-bg-tertiary transition-colors"
                            disabled={actionLoading === member.id}
                          >
                            {actionLoading === member.id ? (
                              <Loader2 size={16} className="animate-spin text-text-tertiary" />
                            ) : (
                              <MoreVertical size={16} className="text-text-tertiary" />
                            )}
                          </button>
                          {menuOpen === member.id && (
                            <div className="absolute right-0 mt-1 w-40 bg-bg-secondary border border-border-primary rounded-lg shadow-xl z-10">
                              {isPending ? (
                                <button
                                  disabled
                                  title="Resend invite API coming soon"
                                  className="w-full px-4 py-2 text-left text-sm flex items-center gap-2 opacity-50 cursor-not-allowed"
                                >
                                  <Mail size={14} />
                                  Resend Invite
                                </button>
                              ) : (
                                <>
                                  {member.role === 'member' && (
                                    <button
                                      onClick={() => handleChangeRole(member.id, 'admin')}
                                      className="w-full px-4 py-2 text-left text-sm hover:bg-bg-hover flex items-center gap-2"
                                    >
                                      <Shield size={14} />
                                      Make Admin
                                    </button>
                                  )}
                                  {member.role === 'admin' && (
                                    <button
                                      onClick={() => handleChangeRole(member.id, 'member')}
                                      className="w-full px-4 py-2 text-left text-sm hover:bg-bg-hover flex items-center gap-2"
                                    >
                                      <User size={14} />
                                      Make Member
                                    </button>
                                  )}
                                </>
                              )}
                              <button
                                onClick={() => handleRemove(member.id)}
                                className="w-full px-4 py-2 text-left text-sm text-error hover:bg-bg-hover flex items-center gap-2"
                              >
                                <Trash2 size={14} />
                                Remove
                              </button>
                            </div>
                          )}
                        </div>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Roles Description */}
      <div className="bg-bg-secondary border border-border-primary rounded-xl p-4">
        <h3 className="text-sm font-medium text-text-primary mb-3">Roles</h3>
        <div className="space-y-2 text-sm text-text-secondary">
          <p><span className="text-warning font-medium">Owner:</span> Full access, billing, can delete team</p>
          <p><span className="text-primary-400 font-medium">Admin:</span> Manage members, projects, settings</p>
          <p><span className="text-text-secondary font-medium">Member:</span> View and run scans, view findings</p>
          <p><span className="text-text-tertiary font-medium">Viewer:</span> Read-only access to view scans and findings</p>
        </div>
      </div>

      {/* Invite Modal */}
      {inviteModalOpen && (
        <InviteMemberModal
          onClose={() => setInviteModalOpen(false)}
          onInvite={handleInvite}
          isLoading={actionLoading === 'invite'}
        />
      )}
    </div>
  );
}

function InviteMemberModal({
  onClose,
  onInvite,
  isLoading,
}: {
  onClose: () => void;
  onInvite: (email: string, role: 'admin' | 'member' | 'viewer') => void;
  isLoading: boolean;
}) {
  const [email, setEmail] = useState('');
  const [role, setRole] = useState<'admin' | 'member' | 'viewer'>('member');

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-bg-secondary border border-border-primary rounded-xl w-full max-w-md">
        <div className="flex items-center justify-between px-6 py-4 border-b border-border-primary">
          <h2 className="text-lg font-semibold text-text-primary">Invite Team Member</h2>
          <button
            onClick={onClose}
            className="p-1 rounded hover:bg-bg-tertiary transition-colors"
            disabled={isLoading}
          >
            <X size={20} className="text-text-tertiary" />
          </button>
        </div>
        <div className="p-6 space-y-4">
          <div>
            <label className="block text-sm font-medium text-text-primary mb-2">
              Email Address
            </label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="colleague@example.com"
              disabled={isLoading}
              className="w-full bg-bg-tertiary border border-border-primary rounded-lg px-4 py-2 text-sm text-text-primary placeholder:text-text-tertiary focus:outline-none focus:border-primary-500 focus:ring-1 focus:ring-primary-500 disabled:opacity-50"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-text-primary mb-2">
              Role
            </label>
            <div className="space-y-2">
              <label className="flex items-center gap-3 p-3 rounded-lg border border-border-primary hover:border-border-secondary cursor-pointer">
                <input
                  type="radio"
                  name="role"
                  value="member"
                  checked={role === 'member'}
                  onChange={() => setRole('member')}
                  disabled={isLoading}
                />
                <div>
                  <p className="font-medium text-text-primary">Member</p>
                  <p className="text-xs text-text-secondary">Can view and run scans, view findings</p>
                </div>
              </label>
              <label className="flex items-center gap-3 p-3 rounded-lg border border-border-primary hover:border-border-secondary cursor-pointer">
                <input
                  type="radio"
                  name="role"
                  value="admin"
                  checked={role === 'admin'}
                  onChange={() => setRole('admin')}
                  disabled={isLoading}
                />
                <div>
                  <p className="font-medium text-text-primary">Admin</p>
                  <p className="text-xs text-text-secondary">Can manage members, projects, and settings</p>
                </div>
              </label>
              <label className="flex items-center gap-3 p-3 rounded-lg border border-border-primary hover:border-border-secondary cursor-pointer">
                <input
                  type="radio"
                  name="role"
                  value="viewer"
                  checked={role === 'viewer'}
                  onChange={() => setRole('viewer')}
                  disabled={isLoading}
                />
                <div>
                  <p className="font-medium text-text-primary">Viewer</p>
                  <p className="text-xs text-text-secondary">Read-only access to view scans and findings</p>
                </div>
              </label>
            </div>
          </div>
        </div>
        <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-border-primary">
          <button
            onClick={onClose}
            disabled={isLoading}
            className="px-4 py-2 text-sm border border-border-primary rounded-lg hover:bg-bg-tertiary transition-colors disabled:opacity-50"
          >
            Cancel
          </button>
          <button
            onClick={() => onInvite(email, role)}
            disabled={!email || isLoading}
            className="px-4 py-2 text-sm bg-primary-500 text-white rounded-lg hover:bg-primary-600 disabled:opacity-50 transition-colors flex items-center gap-2"
          >
            {isLoading && <Loader2 size={14} className="animate-spin" />}
            Send Invite
          </button>
        </div>
      </div>
    </div>
  );
}
