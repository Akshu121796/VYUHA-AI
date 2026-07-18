// In-memory state tracking for asset telemetry (isolation, terminated processes)
const isolatedAssets = new Set<string>();
const initiallyReconnected = new Set<string>();
const terminatedProcesses = new Map<string, Set<number>>();

export function isIsolated(assetId: string, hostname: string): boolean {
  if (isolatedAssets.has(assetId)) {
    return true;
  }
  // Default "db-stage-postgres" to isolated as per mock specifications,
  // unless it has been explicitly reconnected.
  if (hostname === "db-stage-postgres" && !initiallyReconnected.has(assetId)) {
    return true;
  }
  return false;
}

export function toggleIsolation(assetId: string, hostname: string): boolean {
  const current = isIsolated(assetId, hostname);
  if (current) {
    // Reconnect
    isolatedAssets.delete(assetId);
    if (hostname === "db-stage-postgres") {
      initiallyReconnected.add(assetId);
    }
    return false;
  } else {
    // Isolate
    isolatedAssets.add(assetId);
    if (hostname === "db-stage-postgres") {
      initiallyReconnected.delete(assetId);
    }
    return true;
  }
}

export function getTerminatedProcesses(assetId: string): Set<number> {
  if (!terminatedProcesses.has(assetId)) {
    terminatedProcesses.set(assetId, new Set<number>());
  }
  return terminatedProcesses.get(assetId)!;
}

export function terminateProcess(assetId: string, pid: number): void {
  const pids = getTerminatedProcesses(assetId);
  pids.add(pid);
}
