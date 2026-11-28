import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import api, { WS_URL } from './services/api'
import { PUBLIC_DEMO_MODE } from './config'

import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  PieChart,
  Pie,
  Cell,
  Legend,
} from 'recharts'

import {
  Shield,
  LayoutDashboard,
  Activity,
  AlertTriangle,
  Network,
  Settings,
  Search,
  Menu,
  Bell,
  User,
  ChevronDown,
  X,
  Play,
  Square,
  RefreshCw,
  Lock,
  ShieldAlert,
  ShieldCheck,
  Wifi,
  WifiOff,
  SlidersHorizontal,
  Radar,
  Server,
} from 'lucide-react'

const SEVERITY_COLORS = {
  CRITICAL: '#d946ef',
  HIGH: '#ef4444',
  MEDIUM: '#f59e0b',
  LOW: '#22c55e',
}

const MAX_TRAFFIC_ITEMS = 500
const MAX_ALERT_ITEMS = 200

const RISK_STYLES = {
  NONE: 'border-emerald-400/25 bg-emerald-500/10 text-emerald-300',
  LOW: 'border-emerald-400/25 bg-emerald-500/10 text-emerald-300',
  MODERATE: 'border-amber-400/25 bg-amber-500/10 text-amber-300',
  HIGH: 'border-orange-400/25 bg-orange-500/10 text-orange-300',
  VERY_HIGH: 'border-red-400/25 bg-red-500/10 text-red-300',
  UNKNOWN: 'border-slate-500/25 bg-slate-500/10 text-slate-400',
}

const REPUTATION_STATE_LABELS = {
  cached: 'Cached',
  stale: 'Stale',
  refreshed: 'Live',
  unavailable: 'Unavailable',
}

const PROVIDER_ERROR_LABELS = {
  disabled: 'Reputation provider is disabled',
  missing_key: 'Reputation provider is not configured',
  authentication_error: 'Reputation provider rejected the credentials',
  rate_limited: 'Reputation provider rate limit exceeded',
  provider_server_error: 'Reputation provider server error',
  timeout: 'Reputation provider request timed out',
  connection_error: 'Reputation provider is unreachable',
  invalid_response: 'Reputation provider returned an invalid response',
  unexpected_http_error: 'Unexpected reputation provider error',
}

function formatDateTime(value) {
  if (!value) {
    return 'N/A'
  }

  const date = new Date(value)

  return Number.isNaN(date.getTime()) ? 'N/A' : date.toLocaleString()
}

function formatBoolean(value) {
  if (value === null || value === undefined) {
    return 'Unknown'
  }

  return value ? 'Yes' : 'No'
}

function App() {
  const [stats, setStats] = useState({
    total_traffic: 0,
    suspicious_traffic: 0,
    total_alerts: 0,
    normal_traffic: 0,
  })

  const [protocolData, setProtocolData] = useState([])
  const [alertSeverityData, setAlertSeverityData] = useState([])
  const [topSourceIPs, setTopSourceIPs] = useState([])
  const [trafficData, setTrafficData] = useState([])
  const [alertData, setAlertData] = useState([])
    // Packet capture state
  const [captureStatus, setCaptureStatus] = useState({
    status: 'stopped',
    supported: true,
    reason: null,
    interface: null,
    local_ip: null,
    packets_captured: 0,
    last_error: null,
  })

  const [captureLoading, setCaptureLoading] = useState(false)
  const [captureError, setCaptureError] = useState('')

  const [interfaces, setInterfaces] = useState([])
  const [selectedInterface, setSelectedInterface] = useState('')
  const [interfacesLoading, setInterfacesLoading] = useState(false)
  const [interfacesError, setInterfacesError] = useState('')

  const [loading, setLoading] = useState(true)
  const [apiError, setApiError] = useState('')
  const [lastUpdatedAt, setLastUpdatedAt] = useState(null)
  const [now, setNow] = useState(() => Date.now())
  const [updatingAlertId, setUpdatingAlertId] = useState(null)
  const [alertActionError, setAlertActionError] = useState('')
  const [alertAnalyticsError, setAlertAnalyticsError] = useState('')
  const [isNotificationsOpen, setIsNotificationsOpen] = useState(false)
  const [readAlertIds, setReadAlertIds] = useState([])
  const [isSidebarOpen, setIsSidebarOpen] = useState(false)
  const [activeSection, setActiveSection] = useState('dashboard-overview')

  // Alert search and filters
  const [alertSearch, setAlertSearch] = useState('')
  const [severityFilter, setSeverityFilter] = useState('ALL')
  const [trafficDirectionFilter, setTrafficDirectionFilter] = useState('ALL')
  const [trafficProtocolFilter, setTrafficProtocolFilter] = useState('ALL')
  const [statusFilter, setStatusFilter] = useState('ALL')

  // IP reputation lookup
  const [reputationIp, setReputationIp] = useState('')
  const [reputationLoading, setReputationLoading] = useState(false)
  const [reputationResult, setReputationResult] = useState(null)
  const [reputationError, setReputationError] = useState(null)

  // WebSocket connection management
  const [wsStatus, setWsStatus] = useState('connecting')
  const socketRef = useRef(null)
  const reconnectTimerRef = useRef(null)
  const reconnectAttemptsRef = useRef(0)
  const shouldReconnectRef = useRef(true)
  const notificationsRef = useRef(null)
  const isFetchingDashboardRef = useRef(false)
  const trafficWsVersionRef = useRef(0)
  const alertWsVersionRef = useRef(0)

    // Fetch packet capture status
  const fetchCaptureStatus = useCallback(async () => {
    try {
      const response = await api.get('/api/capture/status')
      setCaptureStatus(response.data)
      setCaptureError('')
      return response.data
    } catch (error) {
      console.error('Capture status error:', error)
      setCaptureError('Unable to fetch packet capture status')
    }
  }, [])

  // Look up IP reputation on demand
  const lookupReputation = useCallback(async (event) => {
    event.preventDefault()

    const ipAddress = reputationIp.trim()

    if (!ipAddress) {
      setReputationResult(null)
      setReputationError({
        type: 'invalid',
        message: 'Enter a public IPv4 or IPv6 address.',
      })
      return
    }

    setReputationLoading(true)
    setReputationError(null)

    try {
      const response = await api.get(
        `/api/reputation/${encodeURIComponent(ipAddress)}`
      )
      setReputationResult(response.data)
    } catch (error) {
      setReputationResult(null)

      const status = error.response?.status

      if (status === 400) {
        setReputationError({
          type: 'invalid',
          message: 'Enter a valid public IPv4 or IPv6 address.',
        })
      } else if (status === 503) {
        setReputationError({
          type: 'unavailable',
          message: (
            'IP reputation service is unavailable. '
            + 'It may be disabled on the server.'
          ),
        })
      } else if (status === 429) {
        setReputationError({
          type: 'rate-limit',
          message: 'IP reputation lookup rate limit exceeded. Try again shortly.',
        })
      } else if (status === 403) {
        setReputationError({
          type: 'unavailable',
          message: 'IP reputation lookups are disabled in public demo mode.',
        })
      } else {
        setReputationError({
          type: 'api',
          message: 'Unable to fetch IP reputation.',
        })
      }
    } finally {
      setReputationLoading(false)
    }
  }, [reputationIp])

  // Fetch available network interfaces
  const fetchInterfaces = useCallback(async (activeInterface) => {    try {
      setInterfacesLoading(true)
      setInterfacesError('')

      const response = await api.get('/api/capture/interfaces')
      const availableInterfaces = response.data.interfaces || []

      setInterfaces(availableInterfaces)

      // Keep the user's selection, otherwise prefer the active interface
      setSelectedInterface((currentInterface) => {
        if (currentInterface) {
          return currentInterface
        }

        const preferredInterface = availableInterfaces.find(
          (item) => item.name === activeInterface
        )

        return preferredInterface
          ? preferredInterface.name
          : availableInterfaces[0]?.name || ''
      })

    } catch (error) {
      console.error('Interface fetch error:', error)
      setInterfacesError('Unable to fetch network interfaces')
    } finally {
      setInterfacesLoading(false)
    }
  }, [])

  // Start or stop packet capture
  const handleCaptureAction = async (action) => {
    try {
      setCaptureLoading(true)
      setCaptureError('')

      if (action === 'start') {
        await api.post('/api/capture/start', {
          interface: selectedInterface
        })
      } else {
        await api.post(`/api/capture/${action}`)
      }

      await fetchCaptureStatus()

    } catch (error) {
      console.error('Capture action error:', error)

      setCaptureError(
        error.response?.data?.detail ||
        `Unable to ${action} packet capture. Please try again.`
      )

      await fetchCaptureStatus()

    } finally {
      setCaptureLoading(false)
    }
  }

  // Automatically refresh capture status every 5 seconds
  useEffect(() => {
    const initializeCapture = async () => {
      const status = await fetchCaptureStatus()

      if (status?.supported !== false) {
        await fetchInterfaces(status?.interface)
      }
    }

    initializeCapture()

    const interval = setInterval(fetchCaptureStatus, 5000)

    return () => clearInterval(interval)
  }, [fetchCaptureStatus, fetchInterfaces])
  // Update alert status through the backend API
  const updateAlertStatus = async (alertId, newStatus) => {
    setUpdatingAlertId(alertId)
    setAlertActionError('')
    setAlertAnalyticsError('')

    try {
      let response

      try {
        response = await api.patch(
          `/api/alerts/${alertId}/status`,
          {
            status: newStatus,
          }
        )
      } catch (error) {
        console.error('Alert update error:', error)

        setAlertActionError(
          error.response?.data?.detail ||
          'Unable to update alert status. Please try again.'
        )

        return
      }

      const updatedAlert = response.data.data

      setAlertData((previousAlerts) =>
        previousAlerts.map((alert) =>
          alert.id === alertId ? updatedAlert : alert
        )
      )

      // Refresh analytics after changing alert status
      const [summaryResult, severityResult] = await Promise.allSettled([
        api.get('/api/analytics/summary'),
        api.get('/api/analytics/alerts-by-severity'),
      ])

      const analyticsFailures = []

      if (summaryResult.status === 'fulfilled') {
        setStats(summaryResult.value.data)
      } else {
        console.error('Alert summary refresh error:', summaryResult.reason)
        analyticsFailures.push('summary statistics')
      }

      if (severityResult.status === 'fulfilled') {
        setAlertSeverityData(severityResult.value.data)
      } else {
        console.error('Alert severity refresh error:', severityResult.reason)
        analyticsFailures.push('alert severity data')
      }

      if (analyticsFailures.length > 0) {
        setAlertAnalyticsError(
          `Alert status updated successfully, but ${analyticsFailures.join(' and ')} could not be refreshed.`
        )
      }

    } finally {
      setUpdatingAlertId(null)
    }
  }

  // Mark alert notifications as read
  const markAlertAsRead = (alertId) => {
    setReadAlertIds((previousIds) =>
      previousIds.includes(alertId)
        ? previousIds
        : [...previousIds, alertId]
    )
  }

  const markAllAlertsAsRead = () => {
    setReadAlertIds(alertData.map((alert) => alert.id))
  }

  // Fetch dashboard data
  useEffect(() => {
    let isMounted = true

    const fetchDashboard = async () => {
      if (isFetchingDashboardRef.current) {
        return
      }

      isFetchingDashboardRef.current = true

      try {
        const trafficVersionAtStart = trafficWsVersionRef.current
        const alertVersionAtStart = alertWsVersionRef.current

        const results = await Promise.allSettled([
          api.get('/api/analytics/summary'),
          api.get('/api/analytics/traffic-by-protocol'),
          api.get('/api/analytics/alerts-by-severity'),
          api.get('/api/analytics/top-source-ips?limit=5'),
          api.get('/api/traffic/'),
          api.get('/api/alerts/'),
        ])

        if (!isMounted) return

        const [
          statsResult,
          protocolResult,
          alertSeverityResult,
          topIPsResult,
          trafficResult,
          alertsListResult,
        ] = results

        const failedSections = []

        if (statsResult.status === 'fulfilled') {
          if (updatingAlertId === null) {
            setStats(statsResult.value.data)
          }
        } else {
          failedSections.push('analytics summary')
        }

        if (protocolResult.status === 'fulfilled') {
          setProtocolData(protocolResult.value.data)
        } else {
          failedSections.push('traffic by protocol')
        }

        if (alertSeverityResult.status === 'fulfilled') {
          if (updatingAlertId === null) {
            setAlertSeverityData(alertSeverityResult.value.data)
          }
        } else {
          failedSections.push('alerts by severity')
        }

        if (topIPsResult.status === 'fulfilled') {
          setTopSourceIPs(topIPsResult.value.data)
        } else {
          failedSections.push('top source IPs')
        }

        if (trafficResult.status === 'fulfilled') {
          if (
            trafficVersionAtStart === trafficWsVersionRef.current
          ) {
            setTrafficData(
              trafficResult.value.data.slice(0, MAX_TRAFFIC_ITEMS)
            )
          }
        } else {
          failedSections.push('traffic list')
        }

        if (alertsListResult.status === 'fulfilled') {
          // Do not overwrite alerts during a status update or after a newer event
          if (
            updatingAlertId === null &&
            alertVersionAtStart === alertWsVersionRef.current
          ) {
            setAlertData(
              alertsListResult.value.data.slice(0, MAX_ALERT_ITEMS)
            )
          }
        } else {
          failedSections.push('alerts list')
        }

        if (failedSections.length === 0) {
          setApiError('')
          setAlertAnalyticsError('')
          setLastUpdatedAt(Date.now())
        } else {
          setApiError(
            `Unable to refresh ${failedSections.join(', ')}. Data for those sections was left unchanged.`
          )
        }

      } catch (error) {
        console.error('Dashboard API error:', error)

        if (isMounted) {
          setApiError('Unable to fetch dashboard data')
        }

      } finally {
        isFetchingDashboardRef.current = false

        if (isMounted) {
          setLoading(false)
        }
      }
    }

    fetchDashboard()

    const interval = setInterval(fetchDashboard, 5000)

    return () => {
      isMounted = false
      clearInterval(interval)
    }
  }, [updatingAlertId])

  // Update dashboard freshness clock every 5 seconds
  useEffect(() => {
    const interval = setInterval(() => {
      setNow(Date.now())
    }, 5000)

    return () => clearInterval(interval)
  }, [])

  // Real-time updates through WebSocket
  useEffect(() => {
    shouldReconnectRef.current = true

    const normalizeTimestamps = (record) => {
      if (!record || typeof record.timestamp !== 'string') {
        return record
      }

      if (record.timestamp.endsWith('Z')) {
        return {
          ...record,
          timestamp: record.timestamp.slice(0, -1)
        }
      }

      return record
    }

    const handleEvent = (event) => {
      if (!event || !event.type || !event.data) {
        return
      }

      const data = normalizeTimestamps(event.data)

      if (event.type === 'traffic.created') {
        trafficWsVersionRef.current += 1

        setTrafficData((previousTraffic) => {
          const remainingTraffic = previousTraffic.filter(
            (traffic) => traffic.id !== data.id
          )

          return [data, ...remainingTraffic].slice(0, MAX_TRAFFIC_ITEMS)
        })

        return
      }

      if (event.type === 'alert.created') {
        alertWsVersionRef.current += 1

        setAlertData((previousAlerts) => {
          const remainingAlerts = previousAlerts.filter(
            (alert) => alert.id !== data.id
          )

          return [data, ...remainingAlerts].slice(0, MAX_ALERT_ITEMS)
        })

        return
      }

      if (event.type === 'alert.updated') {
        alertWsVersionRef.current += 1

        setAlertData((previousAlerts) => {
          const alertExists = previousAlerts.some(
            (alert) => alert.id === data.id
          )

          if (!alertExists) {
            return [data, ...previousAlerts].slice(0, MAX_ALERT_ITEMS)
          }

          return previousAlerts.map((alert) =>
            alert.id === data.id
              ? { ...alert, ...data }
              : alert
          )
        })
      }
    }

    const connect = () => {
      if (!shouldReconnectRef.current) {
        return
      }

      const currentSocket = socketRef.current

      if (
        currentSocket &&
        (
          currentSocket.readyState === WebSocket.CONNECTING ||
          currentSocket.readyState === WebSocket.OPEN
        )
      ) {
        return
      }

      if (reconnectTimerRef.current) {
        clearTimeout(reconnectTimerRef.current)
        reconnectTimerRef.current = null
      }

      const socket = new WebSocket(WS_URL)
      socketRef.current = socket

      socket.onopen = () => {
        reconnectAttemptsRef.current = 0
        setWsStatus('connected')
      }

      socket.onmessage = (message) => {
        try {
          const event = JSON.parse(message.data)
          handleEvent(event)
        } catch (error) {
          console.error('WebSocket message error:', error)
        }
      }

      socket.onerror = () => {
        socket.close()
      }

      socket.onclose = () => {
        if (socketRef.current === socket) {
          socketRef.current = null
        }

        setWsStatus(
          shouldReconnectRef.current ? 'reconnecting' : 'disconnected'
        )

        if (!shouldReconnectRef.current || reconnectTimerRef.current) {
          return
        }

        const delay = Math.min(
          1000 * 2 ** reconnectAttemptsRef.current,
          30000
        )

        reconnectAttemptsRef.current += 1

        reconnectTimerRef.current = setTimeout(() => {
          reconnectTimerRef.current = null
          connect()
        }, delay)
      }
    }

    connect()

    return () => {
      shouldReconnectRef.current = false

      if (reconnectTimerRef.current) {
        clearTimeout(reconnectTimerRef.current)
        reconnectTimerRef.current = null
      }

      const socket = socketRef.current

      if (socket) {
        socket.onopen = null
        socket.onmessage = null
        socket.onerror = null
        socket.onclose = null

        try {
          socket.close(1000, 'component unmounted')
        } catch (error) {
          console.error('WebSocket cleanup error:', error)
        }

        socketRef.current = null
      }
    }
  }, [])

  // Close notification panel on outside click or Escape
  useEffect(() => {
    if (!isNotificationsOpen) {
      return
    }

    const handleOutsideClick = (event) => {
      if (
        notificationsRef.current &&
        !notificationsRef.current.contains(event.target)
      ) {
        setIsNotificationsOpen(false)
      }
    }

    const handleEscapeKey = (event) => {
      if (event.key === 'Escape') {
        setIsNotificationsOpen(false)
      }
    }

    document.addEventListener('mousedown', handleOutsideClick)
    document.addEventListener('keydown', handleEscapeKey)

    return () => {
      document.removeEventListener('mousedown', handleOutsideClick)
      document.removeEventListener('keydown', handleEscapeKey)
    }
  }, [isNotificationsOpen])

  // Close mobile sidebar with Escape
  useEffect(() => {
    if (!isSidebarOpen) {
      return
    }

    const handleSidebarEscape = (event) => {
      if (event.key === 'Escape') {
        setIsSidebarOpen(false)
      }
    }

    document.addEventListener('keydown', handleSidebarEscape)

    return () => {
      document.removeEventListener('keydown', handleSidebarEscape)
    }
  }, [isSidebarOpen])

  // Filter network traffic by direction and protocol
  const filteredTraffic = useMemo(
    () =>
      trafficData.filter((traffic) => {
        const matchesDirection =
          trafficDirectionFilter === 'ALL' ||
          traffic.direction === trafficDirectionFilter

        const matchesProtocol =
          trafficProtocolFilter === 'ALL' ||
          traffic.protocol === trafficProtocolFilter

        return matchesDirection && matchesProtocol
      }),
    [trafficData, trafficDirectionFilter, trafficProtocolFilter]
  )

  // Filter alerts based on search, severity, and status
  const filteredAlerts = useMemo(() => {
    const searchValue = alertSearch.trim().toLowerCase()

    return alertData.filter((alert) => {
      const matchesSearch =
        String(alert.source_ip || '').toLowerCase().includes(searchValue) ||
        String(alert.alert_type || '').toLowerCase().includes(searchValue) ||
        String(alert.id).includes(searchValue)

      const matchesSeverity =
        severityFilter === 'ALL' || alert.severity === severityFilter

      const matchesStatus =
        statusFilter === 'ALL' || alert.status === statusFilter

      return matchesSearch && matchesSeverity && matchesStatus
    })
  }, [alertData, alertSearch, severityFilter, statusFilter])

  const recentAlerts = useMemo(() => alertData.slice(0, 5), [alertData])

  const unreadAlerts = useMemo(() => {
    const readAlertIdSet = new Set(readAlertIds)

    return alertData.filter(
      (alert) =>
        alert.status === 'NEW' && !readAlertIdSet.has(alert.id)
    )
  }, [alertData, readAlertIds])

  const activeAlertsCount = useMemo(
    () => alertData.filter((alert) => alert.status !== 'RESOLVED').length,
    [alertData]
  )

  const isDashboardStale =
    Boolean(apiError) ||
    (lastUpdatedAt !== null && now - lastUpdatedAt > 15000) ||
    (!loading && lastUpdatedAt === null)

  const apiStatus = apiError
    ? 'Degraded'
    : lastUpdatedAt === null
      ? 'Checking'
      : 'Operational'

  const formattedLastUpdated = lastUpdatedAt
    ? new Date(lastUpdatedAt).toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false,
      })
    : null

  const handleSectionNavigation = (sectionId) => {
    const section = document.getElementById(sectionId)

    if (section) {
      section.scrollIntoView({ behavior: 'smooth', block: 'start' })
      setActiveSection(sectionId)
    }

    setIsSidebarOpen(false)
  }

  const getNavClass = (sectionId) =>
    `soc-nav-item ${activeSection === sectionId ? 'is-active' : ''}`

  return (
    <div className="soc-app">

      {/* Mobile Sidebar Backdrop */}
      {isSidebarOpen && (
        <div
          className="fixed inset-0 z-30 bg-black/50 lg:hidden"
          onClick={() => setIsSidebarOpen(false)}
          aria-hidden="true"
        />
      )}

      {/* Sidebar */}
      <aside
        id="app-sidebar"
        className={`soc-scroll fixed left-0 top-0 z-40 h-screen w-64 overflow-y-auto border-r border-[rgba(84,112,150,0.22)] bg-[linear-gradient(180deg,#0a1322_0%,#070d18_100%)] p-6 transition-transform duration-200 lg:translate-x-0 ${
          isSidebarOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >

        <div className="mb-10 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="relative rounded-xl bg-gradient-to-br from-blue-500 to-cyan-400 p-2 shadow-[0_12px_30px_-14px_rgba(59,130,246,0.95)] ring-1 ring-white/20">
              <Shield size={25} className="text-white" />
            </div>

            <div>
              <h1 className="soc-title text-xl font-bold tracking-tight text-white">
                SentinelX
              </h1>
              <p className="text-[11px] font-medium uppercase tracking-[0.14em] text-slate-500">
                Network Security
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={() => setIsSidebarOpen(false)}
            className="rounded-lg p-2 text-slate-400 transition hover:bg-[rgba(59,130,246,0.12)] hover:text-white lg:hidden"
            aria-label="Close navigation menu"
          >
            <X size={20} />
          </button>
        </div>

        <p className="soc-eyebrow mb-4">
          Main Menu
        </p>

        <nav className="space-y-1.5">
          <button
            onClick={() => handleSectionNavigation('dashboard-overview')}
            className={getNavClass('dashboard-overview')}
          >
            <LayoutDashboard size={19} />
            Dashboard
          </button>

          <button
            onClick={() => handleSectionNavigation('network-traffic')}
            className={getNavClass('network-traffic')}
          >
            <Activity size={19} />
            Network Traffic
          </button>

          <button
            onClick={() => handleSectionNavigation('security-alerts')}
            className={getNavClass('security-alerts')}
          >
            <AlertTriangle size={19} />
            Security Alerts
          </button>

          <button
            onClick={() => handleSectionNavigation('ip-monitoring')}
            className={getNavClass('ip-monitoring')}
          >
            <Network size={19} />
            IP Monitoring
          </button>
        </nav>

        <div className="absolute bottom-6 left-6 right-6 space-y-3">
          <div className="soc-panel p-3">
            <div className="flex items-center gap-2 text-xs font-medium text-slate-300">
              <span className="soc-dot soc-pulse text-emerald-400" />
              Systems Operational
            </div>
            <p className="mt-1.5 text-[11px] leading-relaxed text-slate-500">
              {PUBLIC_DEMO_MODE
                ? 'Read-only public demo'
                : 'Full monitoring access'}
            </p>
          </div>

          <button
            onClick={() => setIsSidebarOpen(false)}
            className="soc-nav-item"
          >
            <Settings size={19} />
            Settings
          </button>
        </div>
      </aside>

      {/* Main Content */}
      <main className="min-h-screen lg:ml-64">

        {/* Top Navigation */}
        <header className="sticky top-0 z-20 flex min-h-20 flex-wrap items-center justify-between gap-4 border-b border-[rgba(84,112,150,0.2)] bg-[rgba(6,11,20,0.72)] px-4 py-4 backdrop-blur-xl sm:px-6 lg:px-8">

          <div className="flex min-w-0 items-center gap-3">
            <button
              type="button"
              onClick={() => setIsSidebarOpen(true)}
              className="soc-btn soc-btn-ghost h-10 w-10 p-0 lg:hidden"
              aria-label="Open navigation menu"
              aria-controls="app-sidebar"
              aria-expanded={isSidebarOpen}
            >
              <Menu size={20} />
            </button>

            <div className="min-w-0">
              <h2 className="soc-title truncate text-lg font-semibold tracking-tight text-white sm:text-xl">
                Security Dashboard
              </h2>

              <p className="hidden truncate text-xs text-slate-500 sm:block sm:text-sm">
                Monitor your network security in real time
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-3 sm:gap-5">
            <button
              className="soc-btn soc-btn-ghost hidden h-10 w-10 p-0 sm:inline-flex"
              aria-label="Search"
            >
              <Search size={18} />
            </button>

            <div ref={notificationsRef} className="relative">
              <button
                type="button"
                onClick={() => setIsNotificationsOpen((open) => !open)}
                className="soc-btn soc-btn-ghost relative h-10 w-10 p-0"
                aria-label="Security alert notifications"
                aria-expanded={isNotificationsOpen}
              >
                <Bell size={20} />

                {unreadAlerts.length > 0 && (
                  <span className="absolute -right-1.5 -top-1.5 flex h-5 min-w-5 items-center justify-center rounded-full bg-red-500 px-1 text-[10px] font-semibold text-white ring-2 ring-[#060b14]">
                    {unreadAlerts.length > 99 ? '99+' : unreadAlerts.length}
                  </span>
                )}
              </button>

              {isNotificationsOpen && (
                <div className="soc-card soc-fade-up fixed left-4 right-4 top-20 z-30 overflow-hidden sm:absolute sm:left-auto sm:right-0 sm:top-12 sm:w-80">
                  <div className="flex items-center justify-between border-b border-[rgba(84,112,150,0.18)] px-4 py-3">
                    <h4 className="soc-title text-sm font-semibold text-white">
                      Security Alerts
                    </h4>

                    <button
                      type="button"
                      onClick={markAllAlertsAsRead}
                      className="text-xs font-medium text-blue-400 transition hover:text-blue-300"
                    >
                      Mark all read
                    </button>
                  </div>

                  <div className="max-h-80 overflow-y-auto">
                    {recentAlerts.length === 0 ? (
                      <p className="px-4 py-6 text-center text-sm text-slate-500">
                        No recent alerts
                      </p>
                    ) : (
                      recentAlerts.map((alert) => {
                        const isUnread =
                          alert.status === 'NEW' &&
                          !readAlertIds.includes(alert.id)

                        return (
                          <button
                            key={alert.id}
                            type="button"
                            onClick={() => markAlertAsRead(alert.id)}
                            className={`flex w-full items-start gap-3 border-b border-[rgba(84,112,150,0.14)] px-4 py-3 text-left transition last:border-0 hover:bg-blue-500/[0.06] ${
                              isUnread ? 'bg-blue-500/[0.08]' : ''
                            }`}
                          >
                            <span
                              className={`mt-1 h-2 w-2 shrink-0 rounded-full ${
                                alert.severity === 'CRITICAL'
                                  ? 'bg-fuchsia-500'
                                  : alert.severity === 'HIGH'
                                    ? 'bg-red-500'
                                    : alert.severity === 'MEDIUM'
                                      ? 'bg-yellow-500'
                                      : alert.severity === 'LOW'
                                        ? 'bg-green-500'
                                        : 'bg-slate-500'
                              }`}
                            />

                            <span className="min-w-0 flex-1">
                              <span className="block truncate text-sm text-slate-200">
                                {String(alert.alert_type || '').replaceAll('_', ' ')}
                              </span>

                              <span className="block truncate text-xs text-slate-500">
                                {alert.source_ip} ·{' '}
                                {new Date(`${alert.timestamp}Z`).toLocaleString()}
                              </span>
                            </span>

                            <span className="text-[10px] font-medium text-slate-500">
                              {alert.severity}
                            </span>
                          </button>
                        )
                      })
                    )}
                  </div>
                </div>
              )}
            </div>

            <div className="flex items-center gap-2 border-l border-[rgba(84,112,150,0.24)] pl-3 sm:pl-5">
              <div className="rounded-full border border-blue-400/30 bg-blue-500/15 p-2 text-blue-200">
                <User size={17} />
              </div>

              <div className="hidden flex-col sm:flex">
                <span className="text-sm font-medium leading-tight text-slate-200">
                  Administrator
                </span>
                <span className="text-[11px] leading-tight text-slate-500">
                  SOC Analyst
                </span>
              </div>

              <ChevronDown size={15} className="hidden text-slate-500 sm:block" />
            </div>
          </div>
        </header>

        {/* Dashboard Body */}
        <div className="p-4 sm:p-6 lg:p-8">

          {/* Overview */}
          <div id="dashboard-overview" className="soc-fade-up mb-6 scroll-mt-20">
            <div className="flex flex-wrap items-end justify-between gap-4">
              <div>
                <p className="soc-eyebrow mb-2">Security Operations Center</p>

                <h3 className="soc-title soc-gradient-text text-2xl font-bold sm:text-3xl">
                  Overview
                </h3>

                <p className="mt-1.5 text-sm text-slate-500">
                  Your network security at a glance
                </p>
              </div>

              <div className="flex flex-wrap items-center gap-2.5">
                {PUBLIC_DEMO_MODE && (
                  <div className="soc-demo-badge inline-flex items-center gap-2 rounded-xl px-3.5 py-2 text-xs font-semibold sm:text-sm">
                    <Lock size={14} />
                    Public Demo · Read Only
                  </div>
                )}

                <div
                  className={`inline-flex items-center gap-2 rounded-xl border px-3.5 py-2 text-xs font-medium sm:text-sm ${
                    wsStatus === 'connected'
                      ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
                      : wsStatus === 'reconnecting'
                        ? 'border-amber-500/30 bg-amber-500/10 text-amber-300'
                        : wsStatus === 'disconnected'
                          ? 'border-red-500/30 bg-red-500/10 text-red-300'
                          : 'border-amber-500/30 bg-amber-500/10 text-amber-300'
                  }`}
                >
                  {wsStatus === 'connected' ? <Wifi size={15} /> : <WifiOff size={15} />}
                  <span className="soc-dot soc-pulse" />
                  {wsStatus === 'connected'
                    ? 'Live'
                    : wsStatus === 'reconnecting'
                      ? 'Reconnecting'
                      : wsStatus === 'disconnected'
                        ? 'Offline'
                        : 'Connecting'}
                </div>

                <div className={`inline-flex items-center gap-2 rounded-xl border px-3.5 py-2 text-xs font-medium sm:text-sm ${
                  apiStatus === 'Operational'
                    ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
                    : apiStatus === 'Degraded'
                      ? 'border-red-500/30 bg-red-500/10 text-red-300'
                      : 'border-amber-500/30 bg-amber-500/10 text-amber-300'
                }`}>
                  <Server size={15} />
                  API {apiStatus}
                </div>

                <div className="inline-flex items-center gap-2 rounded-xl border border-[rgba(84,112,150,0.24)] bg-[rgba(15,25,43,0.6)] px-3.5 py-2 text-xs text-slate-400 sm:text-sm">
                  <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
                  {formattedLastUpdated
                    ? `Updated ${formattedLastUpdated}`
                    : 'No successful refresh yet'}
                </div>

                {isDashboardStale && (
                  <div className="inline-flex items-center gap-2 rounded-xl border border-amber-500/30 bg-amber-500/10 px-3.5 py-2 text-xs text-amber-300 sm:text-sm">
                    <AlertTriangle size={14} />
                    Data may be stale
                  </div>
                )}
              </div>
            </div>

            {PUBLIC_DEMO_MODE && (
              <div className="soc-demo-banner mt-4 flex items-start gap-3 rounded-xl px-4 py-3 text-sm">
                <Lock size={16} className="mt-0.5 shrink-0" />

                <p className="leading-relaxed">
                  <span className="font-semibold text-sky-200">
                    Read-only demo.
                  </span>{' '}
                  <span className="text-sky-100/80">
                    Traffic and alert data are viewable, but write actions such
                    as capture controls, alert updates, and reputation lookups
                    are disabled.
                  </span>
                </p>
              </div>
            )}
          </div>

          {/* Packet Capture Controls */}
          <div className="soc-card mb-8 p-5 sm:p-6">

            <div className="flex flex-col justify-between gap-5 md:flex-row md:items-center">

              <div>
                <div className="flex flex-wrap items-center gap-3">
                  <span className="rounded-xl border border-blue-400/20 bg-blue-500/10 p-2 text-blue-300">
                    <Radar size={18} />
                  </span>

                  <h3 className="soc-title text-base font-semibold text-white sm:text-lg">
                    Live Packet Capture
                  </h3>

                  <span
                    className={`inline-flex items-center gap-2 rounded-full border px-3 py-1 text-[11px] font-semibold uppercase tracking-wide ${
                      captureStatus.status === 'running'
                        ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
                        : 'border-slate-500/20 bg-slate-500/10 text-slate-400'
                    }`}
                  >
                    <span className={`soc-dot ${captureStatus.status === 'running' ? 'soc-pulse text-emerald-400' : 'text-slate-500'}`} />
                    {captureStatus.status.toUpperCase()}
                  </span>
                </div>

                <p className="mt-2.5 text-sm text-slate-500">
                  Interface: {captureStatus.interface || 'Unknown'}
                  {' | '}
                  Local IP: {captureStatus.local_ip || 'Not detected'}
                </p>
              </div>

              {captureStatus.supported !== false && (
                <div className="flex flex-wrap items-center gap-3">

                {!PUBLIC_DEMO_MODE && (
                  <div className="mr-3">
                    <label
                      htmlFor="capture-interface"
                      className="text-xs text-slate-500"
                    >
                      Network Interface
                    </label>

                  <select
                    id="capture-interface"
                    value={selectedInterface}
                    onChange={(e) => setSelectedInterface(e.target.value)}
                    disabled={
                      captureLoading ||
                      captureStatus.status === 'running'
                    }
                    className="soc-input mt-1 w-full px-4 py-3 text-sm"
                  >
                    {interfaces.length === 0 && (
                      <option value="">
                        {interfacesLoading
                          ? 'Loading interfaces...'
                          : 'No interfaces available'}
                      </option>
                    )}

                    {interfaces.map((networkInterface) => (
                      <option
                        key={networkInterface.name}
                        value={networkInterface.name}
                        title={networkInterface.description}
                      >
                        {networkInterface.name}
                      </option>
                    ))}
                  </select>

                  {selectedInterface && (
                    <p className="mt-1.5 max-w-[16rem] text-xs text-slate-500">
                      {interfaces.find(
                        (item) => item.name === selectedInterface
                      )?.description || ''}
                    </p>
                  )}
                  </div>
                )}

                <div className="mr-3 rounded-xl border border-[rgba(84,112,150,0.2)] bg-[rgba(8,14,26,0.5)] px-4 py-2">
                  <p className="text-[11px] font-medium uppercase tracking-wide text-slate-500">
                    Packets Captured
                  </p>

                  <p className="mt-1 text-2xl font-bold tracking-tight text-blue-300">
                    {captureStatus.packets_captured.toLocaleString()}
                  </p>
                </div>

                {!PUBLIC_DEMO_MODE && (
                  <button
                    onClick={() => handleCaptureAction('start')}
                    disabled={
                      captureLoading ||
                      captureStatus.status === 'running'
                    }
                    className="soc-btn soc-btn-success px-4 py-3 text-sm"
                  >
                    <Play size={17} />

                    {captureLoading ? 'Please wait...' : 'Start Capture'}
                  </button>
                )}

                {!PUBLIC_DEMO_MODE && (
                  <button
                    onClick={() => handleCaptureAction('stop')}
                    disabled={
                      captureLoading ||
                      captureStatus.status !== 'running'
                    }
                    className="soc-btn soc-btn-danger px-4 py-3 text-sm"
                  >
                    <Square size={17} />

                    Stop Capture
                  </button>
                )}

                <button
                  onClick={fetchCaptureStatus}
                  disabled={captureLoading}
                  title="Refresh capture status"
                  className="soc-btn soc-btn-ghost p-3"
                >
                  <RefreshCw size={17} />
                </button>

                </div>
              )}

            </div>

            {captureStatus.supported === false && (
              <div className="mt-4 rounded-xl border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-300">
                {captureStatus.reason || 'Packet capture is not supported in this deployment.'}
              </div>
            )}

            {captureError && (
              <div className="mt-4 rounded-xl border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-300">
                {captureError}
              </div>
            )}

            {interfacesError && (
              <div className="mt-4 rounded-xl border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-300">
                {interfacesError}
              </div>
            )}

          </div>
          {/* API Error */}
          {apiError && (
            <div className="mb-6 rounded-xl border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-300">
              {apiError}
            </div>
          )}

          {/* Statistics Cards */}
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">

            <div className="soc-card soc-card-hover soc-card-glow p-5 sm:p-6">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <p className="text-[11px] font-semibold uppercase tracking-[0.12em] text-slate-400">
                    Total Traffic
                  </p>
                  <h3 className="mt-3 text-3xl font-bold tracking-tight text-white sm:text-4xl">
                    {loading ? '...' : stats.total_traffic}
                  </h3>
                </div>
                <span className="rounded-xl border border-blue-400/25 bg-blue-500/10 p-2.5 text-blue-300">
                  <Activity size={20} />
                </span>
              </div>
              <div className="mt-4 flex items-center gap-2 text-xs text-slate-500">
                <span className="soc-dot text-blue-400" />
                Packets monitored
              </div>
            </div>

            <div className="soc-card soc-card-hover soc-card-glow p-5 sm:p-6">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <p className="text-[11px] font-semibold uppercase tracking-[0.12em] text-slate-400">
                    Suspicious Traffic
                  </p>
                  <h3 className="mt-3 text-3xl font-bold tracking-tight text-red-300 sm:text-4xl">
                    {loading ? '...' : stats.suspicious_traffic}
                  </h3>
                </div>
                <span className="rounded-xl border border-red-400/25 bg-red-500/10 p-2.5 text-red-300">
                  <ShieldAlert size={20} />
                </span>
              </div>
              <div className="mt-4 flex items-center gap-2 text-xs text-slate-500">
                <span className="soc-dot text-red-400" />
                Potential threats detected
              </div>
            </div>

            <div className="soc-card soc-card-hover soc-card-glow p-5 sm:p-6">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <p className="text-[11px] font-semibold uppercase tracking-[0.12em] text-slate-400">
                    Security Alerts
                  </p>
                  <h3 className="mt-3 text-3xl font-bold tracking-tight text-amber-300 sm:text-4xl">
                    {loading ? '...' : stats.total_alerts}
                  </h3>
                </div>
                <span className="rounded-xl border border-amber-400/25 bg-amber-500/10 p-2.5 text-amber-300">
                  <AlertTriangle size={20} />
                </span>
              </div>
              <div className="mt-4 flex items-center gap-2 text-xs text-slate-500">
                <span className="soc-dot text-amber-400" />
                Total generated alerts
              </div>
            </div>

            <div className="soc-card soc-card-hover soc-card-glow p-5 sm:p-6">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <p className="text-[11px] font-semibold uppercase tracking-[0.12em] text-slate-400">
                    Normal Traffic
                  </p>
                  <h3 className="mt-3 text-3xl font-bold tracking-tight text-emerald-300 sm:text-4xl">
                    {loading ? '...' : stats.normal_traffic}
                  </h3>
                </div>
                <span className="rounded-xl border border-emerald-400/25 bg-emerald-500/10 p-2.5 text-emerald-300">
                  <ShieldCheck size={20} />
                </span>
              </div>
              <div className="mt-4 flex items-center gap-2 text-xs text-slate-500">
                <span className="soc-dot text-emerald-400" />
                Normal packets detected
              </div>
            </div>

          </div>

          {/* Analytics Section */}
          <div className="mt-8 grid grid-cols-1 gap-6 xl:grid-cols-2">

            {/* Traffic by Protocol */}
            <div className="soc-card p-5 sm:p-6">

              <h3 className="soc-title text-base font-semibold text-white sm:text-lg">
                Network Traffic Analytics
              </h3>

              <p className="mt-1 text-sm text-slate-500">
                Traffic distribution by protocol
              </p>

              <div className="mt-6 h-64">
                {protocolData.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={protocolData}>
                      <CartesianGrid
                        strokeDasharray="3 3"
                        stroke="#1e293b"
                      />

                      <XAxis dataKey="protocol" stroke="#64748b" />
                      <YAxis stroke="#64748b" />

                      <Tooltip
                        contentStyle={{
                          backgroundColor: '#0b1322',
                          border: '1px solid rgba(96, 165, 250, 0.25)',
                          borderRadius: '12px',
                          color: '#e6edf7',
                          boxShadow: '0 24px 48px -24px rgba(0, 0, 0, 0.95)',
                        }}
                      />

                      <Bar
                        dataKey="total"
                        fill="#3b82f6"
                        radius={[6, 6, 0, 0]}
                      />
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="flex h-full items-center justify-center text-sm text-slate-500">
                    {loading ? 'Loading chart...' : 'No protocol data available'}
                  </div>
                )}
              </div>
            </div>

            {/* Security Alerts by Severity */}
            <div className="soc-card p-5 sm:p-6">

              <h3 className="soc-title text-base font-semibold text-white sm:text-lg">
                Security Alerts
              </h3>

              <p className="mt-1 text-sm text-slate-500">
                Alerts distribution by severity
              </p>

              <div className="mt-6 h-64">
                {alertSeverityData.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={alertSeverityData}
                        dataKey="total"
                        nameKey="severity"
                        cx="50%"
                        cy="45%"
                        outerRadius={85}
                        innerRadius={50}
                        paddingAngle={4}
                        label={({ name, value }) => `${name}: ${value}`}
                      >
                        {alertSeverityData.map((entry, index) => (
                          <Cell
                            key={`cell-${index}`}
                            fill={SEVERITY_COLORS[entry.severity] || '#3b82f6'}
                          />
                        ))}
                      </Pie>

                      <Tooltip
                        contentStyle={{
                          backgroundColor: '#0b1322',
                          border: '1px solid rgba(96, 165, 250, 0.25)',
                          borderRadius: '12px',
                          color: '#e6edf7',
                          boxShadow: '0 24px 48px -24px rgba(0, 0, 0, 0.95)',
                        }}
                      />

                      <Legend />
                    </PieChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="flex h-full items-center justify-center text-sm text-slate-500">
                    {loading ? 'Loading chart...' : 'No security alerts available'}
                  </div>
                )}
              </div>
            </div>

            {/* IP Monitoring */}
            <div id="ip-monitoring" className="scroll-mt-20 grid grid-cols-1 gap-6 xl:col-span-2 xl:grid-cols-3">

              {/* Top Source IPs */}
              <div className="soc-card p-5 sm:p-6 xl:col-span-2">

                <h3 className="soc-title text-base font-semibold text-white sm:text-lg">
                  Top Source IP Addresses
                </h3>

                <p className="mt-1 text-sm text-slate-500">
                  Traffic volume and suspicious traffic by source IP
                </p>

                <div className="mt-6 h-80">
                  {topSourceIPs.length > 0 ? (
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart
                        data={topSourceIPs}
                        layout="vertical"
                        margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
                      >
                        <CartesianGrid
                          strokeDasharray="3 3"
                          stroke="#1e293b"
                        />

                        <XAxis type="number" stroke="#64748b" />

                        <YAxis
                          type="category"
                          dataKey="source_ip"
                          width={120}
                          stroke="#64748b"
                        />

                        <Tooltip
                          contentStyle={{
                            backgroundColor: '#111b2b',
                            border: '1px solid #374151',
                            borderRadius: '8px',
                            color: '#fff',
                          }}
                        />

                        <Legend />

                        <Bar
                          dataKey="total_traffic"
                          name="Total Traffic"
                          fill="#3b82f6"
                          radius={[0, 5, 5, 0]}
                        />

                        <Bar
                          dataKey="suspicious_traffic"
                          name="Suspicious Traffic"
                          fill="#f43f5e"
                          radius={[0, 5, 5, 0]}
                        />

                      </BarChart>
                    </ResponsiveContainer>
                  ) : (
                    <div className="flex h-full items-center justify-center text-sm text-slate-500">
                      {loading ? 'Loading chart...' : 'No source IP data available'}
                    </div>
                  )}
                </div>
              </div>

              {/* IP Reputation Lookup */}
              <div className="soc-card p-5 sm:p-6">

                <h3 className="soc-title text-base font-semibold text-white sm:text-lg">
                  IP Reputation
                </h3>

                <p className="mt-1 text-sm text-slate-500">
                  Check a public IP address against AbuseIPDB
                </p>

                {PUBLIC_DEMO_MODE ? (
                  <div className="soc-panel mt-5 p-3 text-sm text-slate-400">
                    IP reputation lookups are disabled in public demo mode.
                  </div>
                ) : (
                  <form
                    onSubmit={lookupReputation}
                    className="mt-5 flex flex-col gap-3 sm:flex-row xl:flex-col"
                  >
                    <input
                      type="text"
                      value={reputationIp}
                      onChange={(e) => setReputationIp(e.target.value)}
                      placeholder="8.8.8.8 or 2606:4700::1111"
                      aria-label="IP address to check"
                      className="soc-input px-4 py-3 text-sm"
                    />

                    <button
                      type="submit"
                      disabled={reputationLoading}
                      className="soc-btn soc-btn-primary px-4 py-3 text-sm"
                    >
                      <RefreshCw
                        size={16}
                        className={reputationLoading ? 'animate-spin' : ''}
                      />
                      {reputationLoading ? 'Checking...' : 'Check IP'}
                    </button>
                  </form>
                )}

                {reputationError && (
                  <div
                    className={`mt-4 rounded-xl border p-3 text-sm ${
                      reputationError.type === 'invalid'
                        || reputationError.type === 'api'
                        ? 'border-red-500/30 bg-red-500/10 text-red-300'
                        : 'border-amber-500/30 bg-amber-500/10 text-amber-300'
                    }`}
                  >
                    {reputationError.message}
                  </div>
                )}

                {reputationResult && (
                  <div className="mt-5 space-y-4">

                    {reputationResult.provider_error && (
                      <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-300">
                        {PROVIDER_ERROR_LABELS[reputationResult.provider_error]
                          || 'Reputation provider error'}
                      </div>
                    )}

                    <div className="flex flex-wrap items-center gap-2">
                      <span
                        className={`rounded-lg border px-3 py-1 text-xs font-medium ${
                          RISK_STYLES[reputationResult.risk_category]
                            || RISK_STYLES.UNKNOWN
                        }`}
                      >
                        {(reputationResult.risk_category || 'UNKNOWN')
                          .replace('_', ' ')} RISK
                      </span>

                      <span className="soc-panel px-3 py-1 text-xs text-slate-400">
                        {REPUTATION_STATE_LABELS[reputationResult.state]
                          || reputationResult.state}
                      </span>
                    </div>

                    {reputationResult.reputation ? (
                      <>
                        <dl className="grid grid-cols-2 gap-3 text-sm">
                          <div className="col-span-2">
                            <dt className="text-slate-500">IP Address</dt>
                            <dd className="mt-1 break-all font-medium text-white">
                              {reputationResult.ip_address}
                            </dd>
                          </div>

                          <div>
                            <dt className="text-slate-500">Abuse Score</dt>
                            <dd className="mt-1 font-medium text-white">
                              {reputationResult.reputation.abuse_confidence_score
                                ?? 'N/A'}
                            </dd>
                          </div>

                          <div>
                            <dt className="text-slate-500">Total Reports</dt>
                            <dd className="mt-1 font-medium text-white">
                              {reputationResult.reputation.total_reports ?? 'N/A'}
                            </dd>
                          </div>

                          <div>
                            <dt className="text-slate-500">Distinct Users</dt>
                            <dd className="mt-1 font-medium text-white">
                              {reputationResult.reputation.num_distinct_users
                                ?? 'N/A'}
                            </dd>
                          </div>

                          <div>
                            <dt className="text-slate-500">Country</dt>
                            <dd className="mt-1 font-medium text-white">
                              {reputationResult.reputation.country_code || 'N/A'}
                            </dd>
                          </div>

                          <div className="col-span-2">
                            <dt className="text-slate-500">Last Reported</dt>
                            <dd className="mt-1 font-medium text-white">
                              {formatDateTime(
                                reputationResult.reputation.last_reported_at
                              )}
                            </dd>
                          </div>

                          <div className="col-span-2">
                            <dt className="text-slate-500">ISP</dt>
                            <dd className="mt-1 break-words text-white">
                              {reputationResult.reputation.isp || 'N/A'}
                            </dd>
                          </div>

                          <div className="col-span-2">
                            <dt className="text-slate-500">Domain</dt>
                            <dd className="mt-1 break-words text-white">
                              {reputationResult.reputation.domain || 'N/A'}
                            </dd>
                          </div>

                          <div className="col-span-2">
                            <dt className="text-slate-500">Usage Type</dt>
                            <dd className="mt-1 break-words text-white">
                              {reputationResult.reputation.usage_type || 'N/A'}
                            </dd>
                          </div>
                        </dl>

                        <div className="flex flex-wrap gap-2 text-xs text-slate-400">
                          <span className="soc-panel px-3 py-1">
                            Public: {formatBoolean(
                              reputationResult.reputation.is_public
                            )}
                          </span>
                          <span className="soc-panel px-3 py-1">
                            Whitelisted: {formatBoolean(
                              reputationResult.reputation.is_whitelisted
                            )}
                          </span>
                          <span className="soc-panel px-3 py-1">
                            Tor: {formatBoolean(
                              reputationResult.reputation.is_tor
                            )}
                          </span>
                        </div>

                        <p className="text-xs text-slate-500">
                          Cache checked{' '}
                          {formatDateTime(reputationResult.cache?.checked_at)}
                          {reputationResult.cache?.expires_at
                            ? ` · expires ${formatDateTime(
                              reputationResult.cache.expires_at
                            )}`
                            : ''}
                        </p>
                      </>
                    ) : (
                      <p className="text-sm text-slate-500">
                        No reputation data is available for this IP address.
                      </p>
                    )}
                  </div>
                )}
              </div>

            </div>

          </div>

          {/* Recent Network Traffic */}
          <div id="network-traffic" className="mt-8 scroll-mt-20 overflow-hidden soc-card">

            <div className="flex flex-col justify-between gap-4 border-b border-[rgba(84,112,150,0.2)] bg-[rgba(9,16,29,0.35)] p-5 sm:flex-row sm:items-center sm:p-6">

  <div>
    <h3 className="soc-title text-base font-semibold text-white sm:text-lg">
      Recent Network Traffic
    </h3>

    <p className="mt-1 text-sm text-slate-500">
      Latest network packets monitored by SentinelX
    </p>
  </div>

  {/* Traffic Filters */}
  <div className="flex flex-wrap items-center gap-3">

    <span className="hidden items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-slate-500 sm:inline-flex">
      <SlidersHorizontal size={14} />
      Filters
    </span>

    {/* Direction Filter */}
    <select
      value={trafficDirectionFilter}
      onChange={(e) => setTrafficDirectionFilter(e.target.value)}
      aria-label="Filter traffic by direction"
      className="soc-input px-4 py-2.5 text-sm"
    >
      <option value="ALL">All Directions</option>
      <option value="INBOUND">Inbound Traffic</option>
      <option value="OUTBOUND">Outbound Traffic</option>
      <option value="UNKNOWN">Unknown Direction</option>
    </select>

    {/* Protocol Filter */}
    <select
      value={trafficProtocolFilter}
      onChange={(e) => setTrafficProtocolFilter(e.target.value)}
      aria-label="Filter traffic by protocol"
      className="soc-input px-4 py-2.5 text-sm"
    >
      <option value="ALL">All Protocols</option>
      <option value="TCP">TCP</option>
      <option value="UDP">UDP</option>
      <option value="ICMP">ICMP</option>
    </select>

  </div>

</div>
            <div className="overflow-x-auto">
              <table className="soc-table min-w-[900px] text-left text-sm">

                <thead className="text-xs uppercase">
                  <tr>
                    <th className="px-6 py-4">Source IP</th>
                    <th className="px-6 py-4">Destination IP</th>
                    <th className="px-6 py-4">Direction</th>
                    <th className="px-6 py-4">Source Port</th>
                    <th className="px-6 py-4">Dest. Port</th>
                    <th className="px-6 py-4">Protocol</th>
                    <th className="px-6 py-4">Packet Size</th>
                    <th className="px-6 py-4">Status</th>
                    <th className="px-6 py-4">Timestamp</th>
                  </tr>
                </thead>

                <tbody>

                  {filteredTraffic.slice(0, 10).map((traffic) => (

                    <tr key={traffic.id}>

                      <td className="whitespace-nowrap px-6 py-4 text-slate-300">
                        {traffic.source_ip}
                      </td>

                      <td className="whitespace-nowrap px-6 py-4 text-slate-300">
                        {traffic.destination_ip}
                      </td>
                      <td className="px-6 py-4">
                        <span
                          className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-1 text-[11px] font-semibold ${
                            traffic.direction === 'INBOUND'
                              ? 'border-blue-400/20 bg-blue-500/10 text-blue-300'
                              : traffic.direction === 'OUTBOUND'
                                ? 'border-purple-400/20 bg-purple-500/10 text-purple-300'
                                : 'border-slate-500/20 bg-slate-500/10 text-slate-400'
                          }`}
                        >
                          <span className="soc-dot" />
                          {traffic.direction || 'UNKNOWN'}
                        </span>
                        </td>

                      <td className="px-6 py-4 text-slate-400">
                        {traffic.source_port}
                      </td>

                      <td className="px-6 py-4 text-slate-400">
                        {traffic.destination_port}
                      </td>

                      <td className="px-6 py-4">
                        <span className="inline-flex items-center rounded-md border border-blue-400/20 bg-blue-500/10 px-2 py-1 text-[11px] font-medium text-blue-300">
                          {traffic.protocol}
                        </span>
                      </td>

                      <td className="px-6 py-4 text-slate-400">
                        {traffic.packet_size} bytes
                      </td>

                      <td className="px-6 py-4">
                        <span
                          className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-1 text-[11px] font-semibold ${
                            traffic.status === 'suspicious'
                              ? 'border-red-400/25 bg-red-500/10 text-red-300'
                              : 'border-emerald-400/25 bg-emerald-500/10 text-emerald-300'
                          }`}
                        >
                          <span className="soc-dot" />
                          {traffic.status.toUpperCase()}
                        </span>
                      </td>

                      <td className="whitespace-nowrap px-6 py-4 text-slate-400">
                        {new Date(`${traffic.timestamp}Z`).toLocaleString()}
                      </td>

                    </tr>

                  ))}

                  {filteredTraffic.length === 0 && (
                    <tr>
                      <td
                        colSpan="9"
                        className="px-6 py-8 text-center text-slate-500"
                      >
                        No network traffic available
                      </td>
                    </tr>
                  )}

                </tbody>
              </table>
            </div>

            <div className="border-t border-[rgba(84,112,150,0.2)] px-6 py-4 text-xs text-slate-500">
              Showing {Math.min(filteredTraffic.length, 10)} of {filteredTraffic.length} traffic records
            </div>

          </div>

          {/* Security Alerts Management */}
          <div id="security-alerts" className="mt-8 scroll-mt-20 overflow-hidden soc-card">

            <div className="border-b border-[rgba(84,112,150,0.2)] bg-[rgba(9,16,29,0.35)] p-5 sm:p-6">

              <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-center">

                <div>
                  <h3 className="soc-title text-base font-semibold text-white sm:text-lg">
                    Security Alerts Management
                  </h3>

                  <p className="mt-1 text-sm text-slate-500">
                    {PUBLIC_DEMO_MODE
                      ? 'Review detected security threats in read-only mode'
                      : 'Review, acknowledge, and resolve detected security threats'}
                  </p>
                </div>

                <span className="inline-flex items-center gap-2 rounded-xl border border-amber-500/30 bg-amber-500/10 px-3.5 py-2 text-xs font-medium text-amber-300">
                  <span className="soc-dot soc-pulse text-amber-400" />
                  {activeAlertsCount} Active Alerts
                </span>

              </div>

              {/* Search and Filters */}
              <div className="mt-6 grid grid-cols-1 gap-4 md:grid-cols-3">

                {/* Search */}
                <div className="relative">
                  <Search
                    size={18}
                    className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500"
                  />

                  <input
                    type="text"
                    placeholder="Search IP, alert type, or ID..."
                    value={alertSearch}
                    onChange={(e) => setAlertSearch(e.target.value)}
                    aria-label="Search security alerts"
                    className="soc-input py-3 pl-10 pr-4 text-sm"
                  />
                </div>

                {/* Severity Filter */}
                <select
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value)}
                  aria-label="Filter alerts by severity"
                  className="soc-input px-4 py-2.5 text-sm"
                >
                  <option value="ALL">All Severities</option>
                  <option value="CRITICAL">Critical Severity</option>
                  <option value="HIGH">High Severity</option>
                  <option value="MEDIUM">Medium Severity</option>
                  <option value="LOW">Low Severity</option>
                </select>

                {/* Status Filter */}
                <select
                  value={statusFilter}
                  onChange={(e) => setStatusFilter(e.target.value)}
                  aria-label="Filter alerts by status"
                  className="soc-input px-4 py-2.5 text-sm"
                >
                  <option value="ALL">All Statuses</option>
                  <option value="NEW">New</option>
                  <option value="ACKNOWLEDGED">Acknowledged</option>
                  <option value="RESOLVED">Resolved</option>
                </select>

              </div>

              {/* Clear Filters */}
              {(alertSearch || severityFilter !== 'ALL' || statusFilter !== 'ALL') && (
                <button
                  onClick={() => {
                    setAlertSearch('')
                    setSeverityFilter('ALL')
                    setStatusFilter('ALL')
                  }}
                  className="mt-3 inline-flex items-center gap-1.5 text-xs font-medium text-blue-400 transition hover:text-blue-300"
                >
                  <X size={12} />
                  Clear all filters
                </button>
              )}

            </div>

            {/* Alert Action Error */}
            {alertActionError && (
              <div className="m-6 rounded-xl border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-300">
                {alertActionError}
              </div>
            )}

            {/* Alert Analytics Refresh Error */}
            {alertAnalyticsError && (
              <div className="m-6 rounded-xl border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-300">
                {alertAnalyticsError}
              </div>
            )}

            <div className="overflow-x-auto">

              <table className="soc-table min-w-[900px] text-left text-sm">

                <thead className="text-xs uppercase">
                  <tr>
                    <th className="px-6 py-4">Alert ID</th>
                    <th className="px-6 py-4">Source IP</th>
                    <th className="px-6 py-4">Detection Type</th>
                    <th className="px-6 py-4">Severity</th>
                    <th className="px-6 py-4">Status</th>
                    <th className="px-6 py-4">Timestamp</th>
                    {!PUBLIC_DEMO_MODE && (
                      <th className="px-6 py-4">Actions</th>
                    )}
                  </tr>
                </thead>

                <tbody>

                  {filteredAlerts.map((alert) => (

                    <tr key={alert.id}>

                      {/* Alert ID */}
                      <td className="px-6 py-4 font-mono text-xs font-medium text-slate-400">
                        #{alert.id}
                      </td>

                      {/* Source IP */}
                      <td className="whitespace-nowrap px-6 py-4 text-slate-300">
                        {alert.source_ip}
                      </td>

                      {/* Detection Type */}
                      <td className="px-6 py-4 text-slate-300 capitalize">
                        {String(alert.alert_type || '').replaceAll('_', ' ')}
                      </td>

                      {/* Severity */}
                      <td className="px-6 py-4">
                        <span
                          className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-1 text-[11px] font-semibold ${
                            alert.severity === 'CRITICAL'
                              ? 'border-fuchsia-400/30 bg-fuchsia-500/10 text-fuchsia-300'
                              : alert.severity === 'HIGH'
                                ? 'border-red-400/25 bg-red-500/10 text-red-300'
                                : alert.severity === 'MEDIUM'
                                  ? 'border-amber-400/25 bg-amber-500/10 text-amber-300'
                                  : alert.severity === 'LOW'
                                    ? 'border-emerald-400/25 bg-emerald-500/10 text-emerald-300'
                                    : 'border-slate-400/25 bg-slate-500/10 text-slate-300'
                          }`}
                        >
                          <span className="soc-dot" />
                          {alert.severity}
                        </span>
                      </td>

                      {/* Status */}
                      <td className="px-6 py-4">
                        <span
                          className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-1 text-[11px] font-semibold ${
                            alert.status === 'NEW'
                              ? 'border-blue-400/25 bg-blue-500/10 text-blue-300'
                              : alert.status === 'ACKNOWLEDGED'
                                ? 'border-amber-400/25 bg-amber-500/10 text-amber-300'
                                : 'border-emerald-400/25 bg-emerald-500/10 text-emerald-300'
                          }`}
                        >
                          <span className="soc-dot" />
                          {alert.status}
                        </span>
                      </td>

                      {/* Timestamp */}
                      <td className="whitespace-nowrap px-6 py-4 text-slate-400">
                        {new Date(`${alert.timestamp}Z`).toLocaleString()}
                      </td>

                      {/* Actions */}
                      {!PUBLIC_DEMO_MODE && (
                        <td className="px-6 py-4">

                          <div className="flex items-center gap-2">

                          {alert.status === 'NEW' && (
                            <button
                              onClick={() =>
                                updateAlertStatus(alert.id, 'ACKNOWLEDGED')
                              }
                              disabled={updatingAlertId === alert.id}
                              className="soc-btn whitespace-nowrap border-amber-400/25 bg-amber-500/10 px-3 py-2 text-[11px] font-semibold text-amber-300 hover:bg-amber-500/20"
                            >
                              {updatingAlertId === alert.id
                                ? 'Updating...'
                                : 'Acknowledge'}
                            </button>
                          )}

                          {alert.status !== 'RESOLVED' && (
                            <button
                              onClick={() =>
                                updateAlertStatus(alert.id, 'RESOLVED')
                              }
                              disabled={updatingAlertId === alert.id}
                              className="soc-btn whitespace-nowrap border-emerald-400/25 bg-emerald-500/10 px-3 py-2 text-[11px] font-semibold text-emerald-300 hover:bg-emerald-500/20"
                            >
                              {updatingAlertId === alert.id
                                ? 'Updating...'
                                : 'Resolve'}
                            </button>
                          )}

                          {alert.status === 'RESOLVED' && (
                            <span className="inline-flex items-center gap-1.5 text-xs font-medium text-emerald-300">
                              <span className="soc-dot text-emerald-400" />
                              Completed
                            </span>
                          )}

                          </div>

                        </td>
                      )}

                    </tr>

                  ))}

                  {filteredAlerts.length === 0 && (
                    <tr>
                      <td
                        colSpan={PUBLIC_DEMO_MODE ? 6 : 7}
                        className="px-6 py-8 text-center text-slate-500"
                      >
                        No alerts match your search or selected filters.
                      </td>
                    </tr>
                  )}

                </tbody>

              </table>

            </div>

            <div className="border-t border-[rgba(84,112,150,0.2)] px-6 py-4 text-xs text-slate-500">
              Showing {filteredAlerts.length} of {alertData.length} security alerts
            </div>

          </div>

        </div>
      </main>
    </div>
  )
}

export default App