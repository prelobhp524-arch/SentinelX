import axios from 'axios'

const DEFAULT_API_BASE_URL = 'http://127.0.0.1:8000'

const configuredApiBaseUrl = import.meta.env.VITE_API_BASE_URL?.trim()
const configuredWebSocketUrl = import.meta.env.VITE_WS_URL?.trim()

export const API_BASE_URL = (
  configuredApiBaseUrl || DEFAULT_API_BASE_URL
).replace(/\/+$/, '')

export const WS_URL = (
  configuredWebSocketUrl
  || `${API_BASE_URL.replace(/^http/, 'ws')}/ws`
).replace(/\/+$/, '')

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 30000,
})

export default api