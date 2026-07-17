/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_API_BASE_URL?: string;
  readonly VITE_BRIDGE_BASE_URL?: string;
  readonly VITE_BRIDGE_AUDIENCE_URL?: string;
  readonly VITE_APP_URL?: string;
  readonly VITE_DOCS_URL?: string;
  readonly VITE_GITHUB_URL?: string;
  readonly VITE_NETWORK_NAME?: string;
  readonly VITE_NETWORK_ID?: string;
  readonly VITE_CHANNEL_ID?: string;
  readonly VITE_CHANNEL?: string;
  readonly VITE_BACKEND_POLICY?: string;
  readonly VITE_CHAIN_ID?: string;
  readonly VITE_RPC_URL?: string;
  readonly VITE_RPC_URLS?: string;
  readonly VITE_EXPLORER_URL?: string;
  readonly VITE_MAX_INPUT_BYTES?: string;
  readonly VITE_MAX_OUTPUT_TOKENS?: string;
  readonly VITE_PROTOCOL_VERSION?: string;
  readonly VITE_SETTLEMENT_ADDRESS?: string;
  readonly VITE_STABLECOIN_ADDRESS?: string;
  readonly VITE_TOKEN_ADDRESS?: string;
  readonly VITE_TREASURY_ADDRESS?: string;
  readonly VITE_GOVERNANCE_ADDRESS?: string;
  readonly VITE_DEPLOYMENT_BLOCK?: string;
  readonly VITE_STABLECOIN_SYMBOL?: string;
  readonly VITE_STABLECOIN_DECIMALS?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
