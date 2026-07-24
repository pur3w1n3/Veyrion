/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_DEMO_MODE?: string
  readonly VITE_API_BASE_URL?: string
  readonly VITE_PROJECT_ID?: string
  readonly VITE_API_TOKEN?: string
  readonly VITE_SCAN_ID?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
