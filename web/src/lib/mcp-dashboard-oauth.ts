import type { McpOAuthFlow } from "./api";

type CompleteOptions = {
  serverName: string;
  start: (name: string) => Promise<McpOAuthFlow>;
  status: (flowId: string) => Promise<McpOAuthFlow>;
  open: (url?: string | URL, target?: string, features?: string) => unknown;
  sleep?: (milliseconds: number) => Promise<void>;
  maxPollFailures?: number;
  /** Frees the server-side "already in progress" slot for a flow we're abandoning
   * client-side (popup closed, persistent poll failure) before it reached a terminal
   * state. Best-effort: failures here are swallowed so they never mask the real error. */
  cancel?: (flowId: string) => Promise<unknown>;
};

const defaultSleep = (milliseconds: number) =>
  new Promise<void>((resolve) => window.setTimeout(resolve, milliseconds));

export async function completeMcpDashboardOAuth({
  serverName,
  start,
  status,
  open,
  sleep = defaultSleep,
  maxPollFailures = 3,
  cancel,
}: CompleteOptions): Promise<McpOAuthFlow> {
  // Open synchronously from the click handler, before the first await. Browsers
  // otherwise classify the later OAuth popup as unsolicited and block it.
  const authWindow = open("about:blank", "_blank") as Window | null;
  if (!authWindow) {
    throw new Error("OAuth popup was blocked — allow popups for this dashboard and retry");
  }
  authWindow.opener = null;
  let started: McpOAuthFlow;
  try {
    started = await start(serverName);
    if (started.status === "error") {
      throw new Error(started.error || "OAuth failed to start");
    }
    if (!started.authorization_url) {
      throw new Error("OAuth server did not provide an authorization URL");
    }
    authWindow.location.href = started.authorization_url;
  } catch (error) {
    authWindow.close();
    throw error;
  }

  // Frees the "already in progress" slot for `started.flow_id` if we bail out below
  // before the flow reaches approved/error on its own (closed popup, dead poll) —
  // otherwise every retry 409s until the server's own TTL sweep (up to 15 minutes).
  const abandon = async () => {
    if (!cancel) return;
    try {
      await cancel(started.flow_id);
    } catch {
      // best-effort cleanup only; never mask the real error with this one
    }
  };

  let pollFailures = 0;
  for (;;) {
    let current: McpOAuthFlow;
    try {
      current = await status(started.flow_id);
      pollFailures = 0;
    } catch (error) {
      pollFailures += 1;
      if (pollFailures >= maxPollFailures) {
        await abandon();
        throw error;
      }
      await sleep(1000);
      continue;
    }
    if (current.status === "approved") return current;
    if (current.status === "error") {
      throw new Error(current.error || "OAuth authorization failed");
    }
    if (authWindow.closed) {
      await abandon();
      throw new Error("OAuth authorization window was closed before completion");
    }
    await sleep(1000);
  }
}
