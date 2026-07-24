'use client';

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  dashboardApi,
  projectsApi,
  scansApi,
  findingsApi,
  attestationsApi,
  policiesApi,
  reportsApi,
  apiKeysApi,
  teamApi,
  webhooksApi,
  notificationsApi,
  authApi,
} from '@/lib/api';
import type {
  DashboardSummary,
  Project,
  Scan,
  Finding,
  Attestation,
  Policy,
  Report,
  ApiKey,
  TeamMember,
  Webhook,
  Notification,
  User,
  ProjectsFilters,
  ScansFilters,
  FindingsFilters,
  FindingStatus,
  PaginatedResponse,
} from '@/types';

// Query keys
export const queryKeys = {
  dashboard: ['dashboard'] as const,
  projects: {
    all: ['projects'] as const,
    list: (filters?: ProjectsFilters & { page?: number }) =>
      ['projects', 'list', filters] as const,
    detail: (id: string) => ['projects', 'detail', id] as const,
  },
  scans: {
    all: ['scans'] as const,
    list: (filters?: ScansFilters & { page?: number }) =>
      ['scans', 'list', filters] as const,
    detail: (id: string) => ['scans', 'detail', id] as const,
    findings: (scanId: string, params?: { severity?: string[]; page?: number }) =>
      ['scans', scanId, 'findings', params] as const,
  },
  findings: {
    all: ['findings'] as const,
    list: (filters?: FindingsFilters & { page?: number }) =>
      ['findings', 'list', filters] as const,
    detail: (id: string) => ['findings', 'detail', id] as const,
  },
  attestations: {
    all: ['attestations'] as const,
    list: (params?: { projectId?: string; page?: number }) =>
      ['attestations', 'list', params] as const,
    detail: (id: string) => ['attestations', 'detail', id] as const,
  },
  policies: {
    all: ['policies'] as const,
    list: (params?: { page?: number }) => ['policies', 'list', params] as const,
    detail: (id: string) => ['policies', 'detail', id] as const,
  },
  reports: {
    all: ['reports'] as const,
    list: (params?: { page?: number }) => ['reports', 'list', params] as const,
    detail: (id: string) => ['reports', 'detail', id] as const,
  },
  apiKeys: ['api-keys'] as const,
  team: ['team'] as const,
  webhooks: ['webhooks'] as const,
  notifications: ['notifications'] as const,
  user: ['user'] as const,
};

// Dashboard hooks
export function useDashboardSummary() {
  return useQuery<DashboardSummary>({
    queryKey: queryKeys.dashboard,
    queryFn: dashboardApi.getSummary,
    staleTime: 30 * 1000, // 30 seconds
  });
}

// Auth hooks
export function useCurrentUser() {
  return useQuery<User>({
    queryKey: queryKeys.user,
    queryFn: () => authApi.me().then(response => response.user),
    staleTime: 5 * 60 * 1000, // 5 minutes
  });
}

// Projects hooks
export function useProjects(params?: ProjectsFilters & { page?: number; limit?: number }) {
  return useQuery<PaginatedResponse<Project>>({
    queryKey: queryKeys.projects.list(params),
    queryFn: () => projectsApi.list(params),
  });
}

export function useProject(id: string) {
  return useQuery<Project>({
    queryKey: queryKeys.projects.detail(id),
    queryFn: () => projectsApi.get(id),
    enabled: !!id,
  });
}

export function useCreateProject() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: projectsApi.create,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.projects.all });
      queryClient.invalidateQueries({ queryKey: queryKeys.dashboard });
    },
  });
}

export function useUpdateProject() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<Project> }) =>
      projectsApi.update(id, data),
    onSuccess: (_, { id }) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.projects.detail(id) });
      queryClient.invalidateQueries({ queryKey: queryKeys.projects.all });
    },
  });
}

export function useDeleteProject() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: projectsApi.delete,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.projects.all });
      queryClient.invalidateQueries({ queryKey: queryKeys.dashboard });
    },
  });
}

// Scans hooks
export function useScans(params?: ScansFilters & { page?: number; limit?: number }) {
  return useQuery<PaginatedResponse<Scan>>({
    queryKey: queryKeys.scans.list(params),
    queryFn: () => scansApi.list(params),
  });
}

export function useScan(id: string) {
  return useQuery<Scan>({
    queryKey: queryKeys.scans.detail(id),
    queryFn: () => scansApi.get(id),
    enabled: !!id,
    refetchInterval: (query) => {
      // Poll while scan is running
      const scan = query.state.data as Scan | undefined;
      if (scan?.status === 'running' || scan?.status === 'pending') {
        return 3000; // 3 seconds
      }
      return false;
    },
  });
}

export function useCreateScan() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: scansApi.create,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.scans.all });
      queryClient.invalidateQueries({ queryKey: queryKeys.dashboard });
    },
  });
}

export function useCancelScan() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: scansApi.cancel,
    onSuccess: (_, id) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.scans.detail(id) });
      queryClient.invalidateQueries({ queryKey: queryKeys.scans.all });
    },
  });
}

export function useScanFindings(
  scanId: string,
  params?: { severity?: string[]; page?: number; limit?: number }
) {
  return useQuery<PaginatedResponse<Finding>>({
    queryKey: queryKeys.scans.findings(scanId, params),
    queryFn: () => scansApi.getFindings(scanId, params),
    enabled: !!scanId,
  });
}

// Findings hooks
export function useFindings(params?: FindingsFilters & { page?: number; limit?: number }) {
  return useQuery({
    queryKey: queryKeys.findings.list(params),
    queryFn: () => findingsApi.list(params),
  });
}

export function useFinding(id: string) {
  return useQuery<Finding>({
    queryKey: queryKeys.findings.detail(id),
    queryFn: () => findingsApi.get(id),
    enabled: !!id,
  });
}

export function useUpdateFindingStatus() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, status }: { id: string; status: FindingStatus }) =>
      findingsApi.updateStatus(id, status),
    onSuccess: (_, { id }) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.findings.detail(id) });
      queryClient.invalidateQueries({ queryKey: queryKeys.findings.all });
      queryClient.invalidateQueries({ queryKey: queryKeys.dashboard });
    },
  });
}

export function useBulkUpdateFindingStatus() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ ids, status }: { ids: string[]; status: FindingStatus }) =>
      findingsApi.bulkUpdateStatus(ids, status),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.findings.all });
      queryClient.invalidateQueries({ queryKey: queryKeys.dashboard });
    },
  });
}

// Attestations hooks
export function useAttestations(params?: { projectId?: string; page?: number; limit?: number }) {
  return useQuery<PaginatedResponse<Attestation>>({
    queryKey: queryKeys.attestations.list(params),
    queryFn: () => attestationsApi.list(params),
  });
}

export function useAttestation(id: string) {
  return useQuery<Attestation>({
    queryKey: queryKeys.attestations.detail(id),
    queryFn: () => attestationsApi.get(id),
    enabled: !!id,
  });
}

export function useGenerateAttestation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: attestationsApi.generate,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.attestations.all });
    },
  });
}

export function useVerifyAttestation() {
  return useMutation({
    mutationFn: attestationsApi.verify,
  });
}

// Policies hooks
export function usePolicies(params?: { page?: number; limit?: number }) {
  return useQuery<PaginatedResponse<Policy>>({
    queryKey: queryKeys.policies.list(params),
    queryFn: () => policiesApi.list(params),
  });
}

export function usePolicy(id: string) {
  return useQuery<Policy>({
    queryKey: queryKeys.policies.detail(id),
    queryFn: () => policiesApi.get(id),
    enabled: !!id,
  });
}

export function useCreatePolicy() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: policiesApi.create,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.policies.all });
    },
  });
}

export function useUpdatePolicy() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<Policy> }) =>
      policiesApi.update(id, data),
    onSuccess: (_, { id }) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.policies.detail(id) });
      queryClient.invalidateQueries({ queryKey: queryKeys.policies.all });
    },
  });
}

export function useDeletePolicy() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: policiesApi.delete,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.policies.all });
    },
  });
}

// Reports hooks
export function useReports(params?: { page?: number; limit?: number }) {
  return useQuery<PaginatedResponse<Report>>({
    queryKey: queryKeys.reports.list(params),
    queryFn: () => reportsApi.list(params),
  });
}

export function useReport(id: string) {
  return useQuery<Report>({
    queryKey: queryKeys.reports.detail(id),
    queryFn: () => reportsApi.get(id),
    enabled: !!id,
    refetchInterval: (query) => {
      const report = query.state.data as Report | undefined;
      if (report?.status === 'pending') {
        return 5000; // 5 seconds
      }
      return false;
    },
  });
}

export function useGenerateReport() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: reportsApi.generate,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.reports.all });
    },
  });
}

export function useDeleteReport() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: reportsApi.delete,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.reports.all });
    },
  });
}

// API Keys hooks
export function useApiKeys() {
  return useQuery<ApiKey[]>({
    queryKey: queryKeys.apiKeys,
    queryFn: apiKeysApi.list,
  });
}

export function useCreateApiKey() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ name, expiresAt }: { name: string; expiresAt?: string }) =>
      apiKeysApi.create(name, expiresAt),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.apiKeys });
    },
  });
}

export function useDeleteApiKey() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: apiKeysApi.delete,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.apiKeys });
    },
  });
}

// Team hooks
export function useTeam() {
  return useQuery<TeamMember[]>({
    queryKey: queryKeys.team,
    queryFn: teamApi.list,
  });
}

export function useInviteTeamMember() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ email, role }: { email: string; role: TeamMember['role'] }) =>
      teamApi.invite(email, role),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.team });
    },
  });
}

export function useUpdateTeamMemberRole() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, role }: { id: string; role: TeamMember['role'] }) =>
      teamApi.updateRole(id, role),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.team });
    },
  });
}

export function useRemoveTeamMember() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: teamApi.remove,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.team });
    },
  });
}

// Webhooks hooks
export function useWebhooks() {
  return useQuery<Webhook[]>({
    queryKey: queryKeys.webhooks,
    queryFn: webhooksApi.list,
  });
}

export function useCreateWebhook() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: webhooksApi.create,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.webhooks });
    },
  });
}

export function useUpdateWebhook() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<Webhook> }) =>
      webhooksApi.update(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.webhooks });
    },
  });
}

export function useDeleteWebhook() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: webhooksApi.delete,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.webhooks });
    },
  });
}

export function useTestWebhook() {
  return useMutation({
    mutationFn: webhooksApi.test,
  });
}

// Notifications hooks
export function useNotifications() {
  return useQuery<Notification[]>({
    queryKey: queryKeys.notifications,
    queryFn: notificationsApi.list,
    refetchInterval: 60 * 1000, // 1 minute
  });
}

export function useMarkNotificationRead() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: notificationsApi.markRead,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.notifications });
    },
  });
}

export function useMarkAllNotificationsRead() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: notificationsApi.markAllRead,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.notifications });
    },
  });
}
