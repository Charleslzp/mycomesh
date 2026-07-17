import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { protocolApi } from "./api";
import { ApiError } from "./api";

export const protocolQueryKeys = {
  health: ["protocol", "health"] as const,
  discovery: ["protocol", "discovery"] as const,
  models: ["protocol", "models"] as const,
  peers: ["protocol", "peers"] as const,
  account: (credentialId: string) => ["protocol", "account", credentialId] as const,
};

function retryTransient(failureCount: number, error: unknown): boolean {
  if (failureCount >= 2) return false;
  if (!(error instanceof ApiError)) return false;
  return error.status === 0 || error.status === 408 || error.status === 409 || error.status === 429 || error.status >= 500;
}

// Keeps API key material out of React Query keys and developer tooling.
export function credentialCacheId(apiKey: string): string {
  let hash = 0x811c9dc5;
  for (let index = 0; index < apiKey.length; index += 1) {
    hash ^= apiKey.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193);
  }
  return `${apiKey.length}-${(hash >>> 0).toString(16).padStart(8, "0")}`;
}

export function useProxyHealth() {
  return useQuery({
    queryKey: protocolQueryKeys.health,
    queryFn: protocolApi.health,
    retry: retryTransient,
    refetchInterval: 30_000,
    staleTime: 10_000,
  });
}

export function useDiscovery(enabled = true) {
  return useQuery({
    queryKey: protocolQueryKeys.discovery,
    queryFn: protocolApi.discovery,
    enabled,
    retry: retryTransient,
    refetchInterval: 60_000,
    staleTime: 30_000,
  });
}

export function useModels() {
  return useQuery({
    queryKey: protocolQueryKeys.models,
    queryFn: protocolApi.models,
    retry: retryTransient,
    staleTime: 5 * 60_000,
  });
}

export function useProviderPeers() {
  return useQuery({
    queryKey: protocolQueryKeys.peers,
    queryFn: protocolApi.peers,
    retry: retryTransient,
    refetchInterval: 30_000,
    staleTime: 15_000,
  });
}

export function useConsumerAccount(apiKey: string | null | undefined, enabled = true) {
  const credentialId = apiKey ? credentialCacheId(apiKey) : "none";
  return useQuery({
    queryKey: protocolQueryKeys.account(credentialId),
    queryFn: () => protocolApi.account(apiKey ?? ""),
    enabled: Boolean(apiKey) && enabled,
    retry: retryTransient,
    staleTime: 15_000,
  });
}

export function useNetworkSnapshot() {
  const health = useProxyHealth();
  const discovery = useDiscovery();
  const models = useModels();
  const peers = useProviderPeers();

  return useMemo(() => {
    const queries = [health, discovery, models, peers];
    return {
      health: health.data,
      discovery: discovery.data,
      models: models.data,
      peers: peers.data,
      gatewayCount: discovery.data?.gateways?.length,
      providerCount: peers.data?.length,
      modelCount: models.data?.length,
      isPending: queries.some((query) => query.isPending),
      isFetching: queries.some((query) => query.isFetching),
      errors: queries.flatMap((query) => (query.error ? [query.error] : [])),
      refetch: () => Promise.all(queries.map((query) => query.refetch())),
    };
  }, [health, discovery, models, peers]);
}
