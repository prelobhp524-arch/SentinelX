const demoModeValue = import.meta.env?.VITE_PUBLIC_DEMO_MODE

export const PUBLIC_DEMO_MODE = (
  typeof demoModeValue === 'string' &&
  demoModeValue.trim().toLowerCase() === 'true'
)
