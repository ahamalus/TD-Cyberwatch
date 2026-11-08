import { Center, Loader } from "@mantine/core";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { Navigate, useLocation, useParams } from "react-router-dom";
import { api, ApiError } from "./client";
import type { Me, Tenant } from "./types";

export function useMe() {
  return useQuery<Me, ApiError>({
    queryKey: ["me"],
    queryFn: () => api.get<Me>("/auth/me"),
    retry: (count, err) => !(err instanceof ApiError && err.status === 401) && count < 2,
    staleTime: 60_000,
  });
}

export function useRefreshMe() {
  const qc = useQueryClient();
  return () => qc.invalidateQueries({ queryKey: ["me"] });
}

export function RequireAuth({ children }: { children: ReactNode }) {
  const me = useMe();
  const loc = useLocation();
  if (me.isLoading)
    return (
      <Center h="100vh">
        <Loader aria-label="Loading your account" />
      </Center>
    );
  if (me.error && me.error.status === 401) {
    const next = encodeURIComponent(loc.pathname + loc.search);
    return <Navigate to={`/login?next=${next}`} replace />;
  }
  return <>{children}</>;
}

export function useTenantId(): string {
  const { tenantId } = useParams();
  return tenantId ?? "";
}

export function useTenant() {
  const tenantId = useTenantId();
  return useQuery<Tenant, ApiError>({
    queryKey: ["tenant", tenantId],
    queryFn: () => api.get<Tenant>(`/tenants/${tenantId}`),
    enabled: !!tenantId,
    staleTime: 30_000,
  });
}

/** Client-side permission check for showing UI. The backend enforces the same rules. */
export function useCan() {
  const t = useTenant();
  const perms = new Set(t.data?.permissions ?? []);
  return (p: string) => perms.has(p) && !(t.data?.read_only && /:(manage|run|approve|generate)$/.test(p));
}

export function usePlatformCan() {
  const me = useMe();
  const perms = new Set(me.data?.platform_permissions ?? []);
  return (p: string) => perms.has(p);
}
