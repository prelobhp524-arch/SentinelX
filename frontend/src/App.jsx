import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import api, { WS_URL } from './services/api'

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
} from 'lucide-react'

const SEVERITY_COLORS = {
  HIGH: '#ef4444',
  MEDIUM: '#f59e0b',
  LOW: '#22c55e',
}

const MAX_TRAFFIC_ITEMS = 500
const MAX_ALERT_ITEMS = 200

const RISK_STYLES = {
  NONE: 'border-green-500/30 bg-green-500/10 text-green-400',
  LOW: 'border-green-500/30 bg-green-500/10 text-green-400',
  MODERATE: 'border-yellow-500/30 bg-yellow-500/10 text-yellow-400',
  HIGH: 'border-orange-500/30 bg-orange-500/10 text-orange-400',
  VERY_HIGH: 'border-red-500/30 bg-red-500/10 text-red-400',
  UNKNOWN: 'border-gray-600 bg-gray-700/30 text-gray-400',
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
    `flex w-full items-center gap-3 rounded-lg px-4 py-3 text-left transition ${
      activeSection === sectionId
        ? 'bg-blue-600/15 text-blue-400'
        : 'text-gray-400 hover:bg-gray-800 hover:text-white'
    }`

  return (
    <div className="min-h-screen bg-[#080d18] text-gray-200">

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
        className={`fixed left-0 top-0 z-40 h-screen w-64 overflow-y-auto border-r border-gray-800 bg-[#0d1422] p-6 transition-transform duration-200 lg:translate-x-0 ${
          isSidebarOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >

        <div className="mb-10 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="rounded-xl bg-blue-600 p-2">
              <Shield size={25} className="text-white" />
            </div>

            <div>
              <h1 className="text-xl font-bold text-white">SentinelX</h1>
              <p className="text-xs text-gray-500">
                Network Security Monitor
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={() => setIsSidebarOpen(false)}
            className="rounded-lg p-2 text-gray-400 transition hover:bg-gray-800 hover:text-white lg:hidden"
            aria-label="Close navigation menu"
          >
            <X size={20} />
          </button>
        </div>

        <p className="mb-4 text-xs font-semibold uppercase tracking-wider text-gray-500">
          Main Menu
        </p>

        <nav className="space-y-2">
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

        <div className="absolute bottom-6 left-6 right-6">
          <button
            onClick={() => setIsSidebarOpen(false)}
            className="flex w-full items-center gap-3 rounded-lg px-4 py-3 text-gray-400 hover:bg-gray-800 hover:text-white"
          >
            <Settings size={19} />
            Settings
          </button>
        </div>
      </aside>

      {/* Main Content */}
      <main className="min-h-screen lg:ml-64">

        {/* Top Navigation */}
        <header className="sticky top-0 z-20 flex min-h-20 flex-wrap items-center justify-between gap-4 border-b border-gray-800 bg-[#080d18] px-4 py-4 sm:px-6 lg:px-8">

          <div className="flex min-w-0 items-center gap-3">
            <button
              type="button"
              onClick={() => setIsSidebarOpen(true)}
              className="rounded-lg border border-gray-800 p-2 text-gray-400 transition hover:bg-gray-800 hover:text-white lg:hidden"
              aria-label="Open navigation menu"
              aria-controls="app-sidebar"
              aria-expanded={isSidebarOpen}
            >
              <Menu size={20} />
            </button>

            <div className="min-w-0">
              <h2 className="truncate text-lg font-semibold text-white sm:text-xl">
                Security Dashboard
              </h2>

              <p className="hidden truncate text-xs text-gray-500 sm:block sm:text-sm">
                Monitor your network security in real time
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-3 sm:gap-5">
            <button
              className="hidden text-gray-400 hover:text-white sm:block"
              aria-label="Search"
            >
              <Search size={20} />
            </button>

            <div ref={notificationsRef} className="relative">
              <button
                type="button"
                onClick={() => setIsNotificationsOpen((open) => !open)}
                className="relative text-gray-400 hover:text-white"
                aria-label="Security alert notifications"
                aria-expanded={isNotificationsOpen}
              >
                <Bell size={20} />

                {unreadAlerts.length > 0 && (
                  <span className="absolute -right-2 -top-2 flex h-5 min-w-5 items-center justify-center rounded-full bg-red-500 px-1 text-[10px] font-semibold text-white">
                    {unreadAlerts.length > 99 ? '99+' : unreadAlerts.length}
                  </span>
                )}
              </button>

              {isNotificationsOpen && (
                <div className="fixed left-4 right-4 top-20 z-20 rounded-xl border border-gray-800 bg-[#111b2b] shadow-xl sm:absolute sm:left-auto sm:right-0 sm:top-12 sm:w-80">
                  <div className="flex items-center justify-between border-b border-gray-800 px-4 py-3">
                    <h4 className="text-sm font-semibold text-white">
                      Security Alerts
                    </h4>

                    <button
                      type="button"
                      onClick={markAllAlertsAsRead}
                      className="text-xs text-blue-400 transition hover:text-blue-300"
                    >
                      Mark all read
                    </button>
                  </div>

                  <div className="max-h-80 overflow-y-auto">
                    {recentAlerts.length === 0 ? (
                      <p className="px-4 py-6 text-center text-sm text-gray-500">
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
                            className={`flex w-full items-start gap-3 border-b border-gray-800 px-4 py-3 text-left transition last:border-0 hover:bg-gray-800/40 ${
                              isUnread ? 'bg-blue-500/10' : ''
                            }`}
                          >
                            <span
                              className={`mt-1 h-2 w-2 shrink-0 rounded-full ${
                                alert.severity === 'HIGH'
                                  ? 'bg-red-500'
                                  : alert.severity === 'MEDIUM'
                                    ? 'bg-yellow-500'
                                    : 'bg-green-500'
                              }`}
                            />

                            <span className="min-w-0 flex-1">
                              <span className="block truncate text-sm text-gray-200">
                                {String(alert.alert_type || '').replaceAll('_', ' ')}
                              </span>

                              <span className="block truncate text-xs text-gray-500">
                                {alert.source_ip} ·{' '}
                                {new Date(`${alert.timestamp}Z`).toLocaleString()}
                              </span>
                            </span>

                            <span className="text-[10px] font-medium text-gray-500">
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

            <div className="flex items-center gap-2 border-l border-gray-800 pl-3 sm:pl-5">
              <div className="rounded-full bg-gray-700 p-2">
                <User size={18} />
              </div>

              <span className="hidden text-sm text-gray-300 sm:inline">
                Administrator
              </span>

              <ChevronDown size={15} className="hidden text-gray-500 sm:block" />
            </div>
          </div>
        </header>

        {/* Dashboard Body */}
        <div className="p-4 sm:p-6 lg:p-8">

          {/* Overview */}
          <div id="dashboard-overview" className="mb-8 flex scroll-mt-20 flex-wrap items-center justify-between gap-4">
            <div>
              <h3 className="text-2xl font-bold text-white">
                Overview
              </h3>

              <p className="mt-1 text-sm text-gray-500">
                Your network security at a glance
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-3">
              <div
                className={`rounded-lg border px-4 py-2 text-sm ${
                  wsStatus === 'connected'
                    ? 'border-green-500/30 bg-green-500/10 text-green-400'
                    : wsStatus === 'reconnecting'
                      ? 'border-orange-500/30 bg-orange-500/10 text-orange-400'
                      : wsStatus === 'disconnected'
                        ? 'border-red-500/30 bg-red-500/10 text-red-400'
                        : 'border-amber-500/30 bg-amber-500/10 text-amber-400'
                }`}
              >
                ● {wsStatus === 'connected'
                  ? 'Connected'
                  : wsStatus === 'reconnecting'
                    ? 'Reconnecting'
                    : wsStatus === 'disconnected'
                      ? 'Disconnected'
                      : 'Connecting'}
              </div>

              <div className={`rounded-lg border px-4 py-2 text-sm ${
                apiStatus === 'Operational'
                  ? 'border-green-500/30 bg-green-500/10 text-green-400'
                  : apiStatus === 'Degraded'
                    ? 'border-red-500/30 bg-red-500/10 text-red-400'
                    : 'border-amber-500/30 bg-amber-500/10 text-amber-400'
              }`}>
                ● API: {apiStatus}
              </div>

              <div className="rounded-lg border border-gray-700 bg-gray-800/40 px-4 py-2 text-sm text-gray-400">
                {formattedLastUpdated
                  ? `Updated ${formattedLastUpdated}`
                  : 'No successful refresh yet'}
              </div>

              {isDashboardStale && (
                <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-2 text-sm text-amber-400">
                  Data may be stale
                </div>
              )}
            </div>
          </div>
                    {/* Packet Capture Controls */}
          <div className="mb-8 rounded-xl border border-gray-800 bg-[#111b2b] p-6">

            <div className="flex flex-col justify-between gap-5 md:flex-row md:items-center">

              <div>
                <div className="flex items-center gap-3">
                  <Activity size={22} className="text-blue-400" />

                  <h3 className="text-lg font-semibold text-white">
                    Live Packet Capture
                  </h3>

                  <span
                    className={`rounded-full px-3 py-1 text-xs font-semibold ${
                      captureStatus.status === 'running'
                        ? 'bg-green-500/10 text-green-400'
                        : 'bg-gray-500/10 text-gray-400'
                    }`}
                  >
                    ● {captureStatus.status.toUpperCase()}
                  </span>
                </div>

                <p className="mt-2 text-sm text-gray-500">
                  Interface: {captureStatus.interface || 'Unknown'}
                  {' | '}
                  Local IP: {captureStatus.local_ip || 'Not detected'}
                </p>
              </div>

              {captureStatus.supported !== false && (
                <div className="flex flex-wrap items-center gap-3">

                <div className="mr-3">
                  <label
                    htmlFor="capture-interface"
                    className="text-xs text-gray-500"
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
                    className="mt-1 w-full rounded-lg border border-gray-700 bg-[#0d1422] px-4 py-3 text-sm text-gray-300 outline-none focus:border-blue-500 disabled:cursor-not-allowed disabled:opacity-40"
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
                    <p className="mt-1 max-w-[16rem] text-xs text-gray-500">
                      {interfaces.find(
                        (item) => item.name === selectedInterface
                      )?.description || ''}
                    </p>
                  )}
                </div>

                <div className="mr-3">
                  <p className="text-xs text-gray-500">
                    Packets Captured
                  </p>

                  <p className="text-2xl font-bold text-blue-400">
                    {captureStatus.packets_captured.toLocaleString()}
                  </p>
                </div>

                <button
                  onClick={() => handleCaptureAction('start')}
                  disabled={
                    captureLoading ||
                    captureStatus.status === 'running'
                  }
                  className="flex items-center gap-2 rounded-lg bg-green-600 px-4 py-3 text-sm font-semibold text-white transition hover:bg-green-500 disabled:cursor-not-allowed disabled:opacity-40"
                >
                  <Play size={17} />

                  {captureLoading ? 'Please wait...' : 'Start Capture'}
                </button>

                <button
                  onClick={() => handleCaptureAction('stop')}
                  disabled={
                    captureLoading ||
                    captureStatus.status !== 'running'
                  }
                  className="flex items-center gap-2 rounded-lg bg-red-600 px-4 py-3 text-sm font-semibold text-white transition hover:bg-red-500 disabled:cursor-not-allowed disabled:opacity-40"
                >
                  <Square size={17} />

                  Stop Capture
                </button>

                <button
                  onClick={fetchCaptureStatus}
                  disabled={captureLoading}
                  title="Refresh capture status"
                  className="rounded-lg border border-gray-700 p-3 text-gray-400 transition hover:bg-gray-800 hover:text-white"
                >
                  <RefreshCw size={17} />
                </button>

                </div>
              )}

            </div>

            {captureStatus.supported === false && (
              <div className="mt-4 rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-300">
                {captureStatus.reason || 'Packet capture is not supported in this deployment.'}
              </div>
            )}

            {captureError && (
              <div className="mt-4 rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-400">
                {captureError}
              </div>
            )}

            {interfacesError && (
              <div className="mt-4 rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-400">
                {interfacesError}
              </div>
            )}

          </div>
          {/* API Error */}
          {apiError && (
            <div className="mb-6 rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-400">
              {apiError}
            </div>
          )}

          {/* Statistics Cards */}
          <div className="grid grid-cols-1 gap-5 md:grid-cols-2 xl:grid-cols-4">

            <div className="rounded-xl border border-gray-800 bg-[#111b2b] p-6">
              <p className="text-sm text-gray-400">Total Traffic</p>
              <h3 className="mt-3 text-3xl font-bold text-white">
                {loading ? '...' : stats.total_traffic}
              </h3>
              <p className="mt-2 text-xs text-gray-500">
                Packets monitored
              </p>
            </div>

            <div className="rounded-xl border border-gray-800 bg-[#111b2b] p-6">
              <p className="text-sm text-gray-400">Suspicious Traffic</p>
              <h3 className="mt-3 text-3xl font-bold text-red-400">
                {loading ? '...' : stats.suspicious_traffic}
              </h3>
              <p className="mt-2 text-xs text-gray-500">
                Potential threats detected
              </p>
            </div>

            <div className="rounded-xl border border-gray-800 bg-[#111b2b] p-6">
              <p className="text-sm text-gray-400">Security Alerts</p>
              <h3 className="mt-3 text-3xl font-bold text-yellow-400">
                {loading ? '...' : stats.total_alerts}
              </h3>
              <p className="mt-2 text-xs text-gray-500">
                Total generated alerts
              </p>
            </div>

            <div className="rounded-xl border border-gray-800 bg-[#111b2b] p-6">
              <p className="text-sm text-gray-400">Normal Traffic</p>
              <h3 className="mt-3 text-3xl font-bold text-green-400">
                {loading ? '...' : stats.normal_traffic}
              </h3>
              <p className="mt-2 text-xs text-gray-500">
                Normal packets detected
              </p>
            </div>

          </div>

          {/* Analytics Section */}
          <div className="mt-8 grid grid-cols-1 gap-6 xl:grid-cols-2">

            {/* Traffic by Protocol */}
            <div className="rounded-xl border border-gray-800 bg-[#111b2b] p-6">

              <h3 className="text-lg font-semibold text-white">
                Network Traffic Analytics
              </h3>

              <p className="mt-1 text-sm text-gray-500">
                Traffic distribution by protocol
              </p>

              <div className="mt-6 h-64">
                {protocolData.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={protocolData}>
                      <CartesianGrid
                        strokeDasharray="3 3"
                        stroke="#273449"
                      />

                      <XAxis dataKey="protocol" stroke="#9ca3af" />
                      <YAxis stroke="#9ca3af" />

                      <Tooltip
                        contentStyle={{
                          backgroundColor: '#111b2b',
                          border: '1px solid #374151',
                          borderRadius: '8px',
                          color: '#fff',
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
                  <div className="flex h-full items-center justify-center text-sm text-gray-500">
                    {loading ? 'Loading chart...' : 'No protocol data available'}
                  </div>
                )}
              </div>
            </div>

            {/* Security Alerts by Severity */}
            <div className="rounded-xl border border-gray-800 bg-[#111b2b] p-6">

              <h3 className="text-lg font-semibold text-white">
                Security Alerts
              </h3>

              <p className="mt-1 text-sm text-gray-500">
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
                          backgroundColor: '#111b2b',
                          border: '1px solid #374151',
                          borderRadius: '8px',
                          color: '#fff',
                        }}
                      />

                      <Legend />
                    </PieChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="flex h-full items-center justify-center text-sm text-gray-500">
                    {loading ? 'Loading chart...' : 'No security alerts available'}
                  </div>
                )}
              </div>
            </div>

            {/* IP Monitoring */}
            <div id="ip-monitoring" className="scroll-mt-20 grid grid-cols-1 gap-6 xl:col-span-2 xl:grid-cols-3">

              {/* Top Source IPs */}
              <div className="rounded-xl border border-gray-800 bg-[#111b2b] p-6 xl:col-span-2">

                <h3 className="text-lg font-semibold text-white">
                  Top Source IP Addresses
                </h3>

                <p className="mt-1 text-sm text-gray-500">
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
                          stroke="#273449"
                        />

                        <XAxis type="number" stroke="#9ca3af" />

                        <YAxis
                          type="category"
                          dataKey="source_ip"
                          width={120}
                          stroke="#9ca3af"
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
                          fill="#ef4444"
                          radius={[0, 5, 5, 0]}
                        />

                      </BarChart>
                    </ResponsiveContainer>
                  ) : (
                    <div className="flex h-full items-center justify-center text-sm text-gray-500">
                      {loading ? 'Loading chart...' : 'No source IP data available'}
                    </div>
                  )}
                </div>
              </div>

              {/* IP Reputation Lookup */}
              <div className="rounded-xl border border-gray-800 bg-[#111b2b] p-6">

                <h3 className="text-lg font-semibold text-white">
                  IP Reputation
                </h3>

                <p className="mt-1 text-sm text-gray-500">
                  Check a public IP address against AbuseIPDB
                </p>

                <form
                  onSubmit={lookupReputation}
                  className="mt-5 flex flex-col gap-3 sm:flex-row xl:flex-col"
                >
                  <input
                    type="text"
                    value={reputationIp}
                    onChange={(e) => setReputationIp(e.target.value)}
                    placeholder="8.8.8.8 or 2606:4700::1111"
                    className="w-full rounded-lg border border-gray-700 bg-[#0d1422] px-4 py-3 text-sm text-white outline-none placeholder:text-gray-500 focus:border-blue-500"
                  />

                  <button
                    type="submit"
                    disabled={reputationLoading}
                    className="inline-flex items-center justify-center gap-2 rounded-lg bg-blue-600 px-4 py-3 text-sm font-medium text-white transition hover:bg-blue-500 disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    <RefreshCw
                      size={16}
                      className={reputationLoading ? 'animate-spin' : ''}
                    />
                    {reputationLoading ? 'Checking...' : 'Check IP'}
                  </button>
                </form>

                {reputationError && (
                  <div
                    className={`mt-4 rounded-lg border p-3 text-sm ${
                      reputationError.type === 'invalid'
                        || reputationError.type === 'api'
                        ? 'border-red-500/30 bg-red-500/10 text-red-400'
                        : 'border-yellow-500/30 bg-yellow-500/10 text-yellow-400'
                    }`}
                  >
                    {reputationError.message}
                  </div>
                )}

                {reputationResult && (
                  <div className="mt-5 space-y-4">

                    {reputationResult.provider_error && (
                      <div className="rounded-lg border border-yellow-500/30 bg-yellow-500/10 p-3 text-sm text-yellow-400">
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

                      <span className="rounded-lg border border-gray-700 bg-[#0d1422] px-3 py-1 text-xs text-gray-400">
                        {REPUTATION_STATE_LABELS[reputationResult.state]
                          || reputationResult.state}
                      </span>
                    </div>

                    {reputationResult.reputation ? (
                      <>
                        <dl className="grid grid-cols-2 gap-3 text-sm">
                          <div className="col-span-2">
                            <dt className="text-gray-500">IP Address</dt>
                            <dd className="mt-1 break-all font-medium text-white">
                              {reputationResult.ip_address}
                            </dd>
                          </div>

                          <div>
                            <dt className="text-gray-500">Abuse Score</dt>
                            <dd className="mt-1 font-medium text-white">
                              {reputationResult.reputation.abuse_confidence_score
                                ?? 'N/A'}
                            </dd>
                          </div>

                          <div>
                            <dt className="text-gray-500">Total Reports</dt>
                            <dd className="mt-1 font-medium text-white">
                              {reputationResult.reputation.total_reports ?? 'N/A'}
                            </dd>
                          </div>

                          <div>
                            <dt className="text-gray-500">Distinct Users</dt>
                            <dd className="mt-1 font-medium text-white">
                              {reputationResult.reputation.num_distinct_users
                                ?? 'N/A'}
                            </dd>
                          </div>

                          <div>
                            <dt className="text-gray-500">Country</dt>
                            <dd className="mt-1 font-medium text-white">
                              {reputationResult.reputation.country_code || 'N/A'}
                            </dd>
                          </div>

                          <div className="col-span-2">
                            <dt className="text-gray-500">Last Reported</dt>
                            <dd className="mt-1 font-medium text-white">
                              {formatDateTime(
                                reputationResult.reputation.last_reported_at
                              )}
                            </dd>
                          </div>

                          <div className="col-span-2">
                            <dt className="text-gray-500">ISP</dt>
                            <dd className="mt-1 break-words text-white">
                              {reputationResult.reputation.isp || 'N/A'}
                            </dd>
                          </div>

                          <div className="col-span-2">
                            <dt className="text-gray-500">Domain</dt>
                            <dd className="mt-1 break-words text-white">
                              {reputationResult.reputation.domain || 'N/A'}
                            </dd>
                          </div>

                          <div className="col-span-2">
                            <dt className="text-gray-500">Usage Type</dt>
                            <dd className="mt-1 break-words text-white">
                              {reputationResult.reputation.usage_type || 'N/A'}
                            </dd>
                          </div>
                        </dl>

                        <div className="flex flex-wrap gap-2 text-xs text-gray-400">
                          <span className="rounded-lg border border-gray-700 bg-[#0d1422] px-3 py-1">
                            Public: {formatBoolean(
                              reputationResult.reputation.is_public
                            )}
                          </span>
                          <span className="rounded-lg border border-gray-700 bg-[#0d1422] px-3 py-1">
                            Whitelisted: {formatBoolean(
                              reputationResult.reputation.is_whitelisted
                            )}
                          </span>
                          <span className="rounded-lg border border-gray-700 bg-[#0d1422] px-3 py-1">
                            Tor: {formatBoolean(
                              reputationResult.reputation.is_tor
                            )}
                          </span>
                        </div>

                        <p className="text-xs text-gray-500">
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
                      <p className="text-sm text-gray-500">
                        No reputation data is available for this IP address.
                      </p>
                    )}
                  </div>
                )}
              </div>

            </div>

          </div>

          {/* Recent Network Traffic */}
          <div id="network-traffic" className="mt-8 scroll-mt-20 overflow-hidden rounded-xl border border-gray-800 bg-[#111b2b]">

            <div className="flex flex-col justify-between gap-4 border-b border-gray-800 p-6 sm:flex-row sm:items-center">

  <div>
    <h3 className="text-lg font-semibold text-white">
      Recent Network Traffic
    </h3>

    <p className="mt-1 text-sm text-gray-500">
      Latest network packets monitored by SentinelX
    </p>
  </div>

  {/* Traffic Filters */}
  <div className="flex flex-wrap gap-3">

    {/* Direction Filter */}
    <select
      value={trafficDirectionFilter}
      onChange={(e) => setTrafficDirectionFilter(e.target.value)}
      className="rounded-lg border border-gray-700 bg-[#0d1422] px-4 py-3 text-sm text-gray-300 outline-none focus:border-blue-500"
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
      className="rounded-lg border border-gray-700 bg-[#0d1422] px-4 py-3 text-sm text-gray-300 outline-none focus:border-blue-500"
    >
      <option value="ALL">All Protocols</option>
      <option value="TCP">TCP</option>
      <option value="UDP">UDP</option>
      <option value="ICMP">ICMP</option>
    </select>

  </div>

</div>
            <div className="overflow-x-auto">
              <table className="w-full min-w-[900px] text-left text-sm">

                <thead className="bg-[#0d1422] text-xs uppercase text-gray-400">
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

                <tbody className="divide-y divide-gray-800">

                  {filteredTraffic.slice(0, 10).map((traffic) => (

                    <tr
                      key={traffic.id}
                      className="transition-colors hover:bg-gray-800/40"
                    >

                      <td className="whitespace-nowrap px-6 py-4 text-gray-300">
                        {traffic.source_ip}
                      </td>

                      <td className="whitespace-nowrap px-6 py-4 text-gray-300">
                        {traffic.destination_ip}
                      </td>
                      <td className="px-6 py-4">
                         <span
                            className={`rounded-md px-2 py-1 text-xs font-semibold ${
                              traffic.direction === 'INBOUND'
                            ? 'bg-blue-500/10 text-blue-400'
                            : traffic.direction === 'OUTBOUND'
                            ? 'bg-purple-500/10 text-purple-400'
                           : 'bg-gray-500/10 text-gray-400'
                       }`}
                      >
                        {traffic.direction || 'UNKNOWN'}
                          </span>
                        </td>

                      <td className="px-6 py-4 text-gray-400">
                        {traffic.source_port}
                      </td>

                      <td className="px-6 py-4 text-gray-400">
                        {traffic.destination_port}
                      </td>

                      <td className="px-6 py-4">
                        <span className="rounded-md bg-blue-500/10 px-2 py-1 text-xs text-blue-400">
                          {traffic.protocol}
                        </span>
                      </td>

                      <td className="px-6 py-4 text-gray-400">
                        {traffic.packet_size} bytes
                      </td>

                      <td className="px-6 py-4">
                        <span
                          className={`rounded-md px-2 py-1 text-xs font-medium ${
                            traffic.status === 'suspicious'
                              ? 'bg-red-500/10 text-red-400'
                              : 'bg-green-500/10 text-green-400'
                          }`}
                        >
                          {traffic.status.toUpperCase()}
                        </span>
                      </td>

                      <td className="whitespace-nowrap px-6 py-4 text-gray-400">
                        {new Date(`${traffic.timestamp}Z`).toLocaleString()}
                      </td>

                    </tr>

                  ))}

                  {filteredTraffic.length === 0 && (
                    <tr>
                      <td
                        colSpan="9"
                        className="px-6 py-8 text-center text-gray-500"
                      >
                        No network traffic available
                      </td>
                    </tr>
                  )}

                </tbody>
              </table>
            </div>

            <div className="border-t border-gray-800 px-6 py-4 text-xs text-gray-500">
              Showing {Math.min(filteredTraffic.length, 10)} of {filteredTraffic.length} traffic records
            </div>

          </div>

          {/* Security Alerts Management */}
          <div id="security-alerts" className="mt-8 scroll-mt-20 overflow-hidden rounded-xl border border-gray-800 bg-[#111b2b]">

            <div className="border-b border-gray-800 p-6">

              <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-center">

                <div>
                  <h3 className="text-lg font-semibold text-white">
                    Security Alerts Management
                  </h3>

                  <p className="mt-1 text-sm text-gray-500">
                    Review, acknowledge, and resolve detected security threats
                  </p>
                </div>

                <span className="rounded-lg border border-yellow-500/30 bg-yellow-500/10 px-3 py-2 text-xs text-yellow-400">
                  {activeAlertsCount} Active Alerts
                </span>

              </div>

              {/* Search and Filters */}
              <div className="mt-6 grid grid-cols-1 gap-4 md:grid-cols-3">

                {/* Search */}
                <div className="relative">
                  <Search
                    size={18}
                    className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500"
                  />

                  <input
                    type="text"
                    placeholder="Search IP, alert type, or ID..."
                    value={alertSearch}
                    onChange={(e) => setAlertSearch(e.target.value)}
                    className="w-full rounded-lg border border-gray-700 bg-[#0d1422] py-3 pl-10 pr-4 text-sm text-white outline-none placeholder:text-gray-500 focus:border-blue-500"
                  />
                </div>

                {/* Severity Filter */}
                <select
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value)}
                  className="rounded-lg border border-gray-700 bg-[#0d1422] px-4 py-3 text-sm text-gray-300 outline-none focus:border-blue-500"
                >
                  <option value="ALL">All Severities</option>
                  <option value="HIGH">High Severity</option>
                  <option value="MEDIUM">Medium Severity</option>
                  <option value="LOW">Low Severity</option>
                </select>

                {/* Status Filter */}
                <select
                  value={statusFilter}
                  onChange={(e) => setStatusFilter(e.target.value)}
                  className="rounded-lg border border-gray-700 bg-[#0d1422] px-4 py-3 text-sm text-gray-300 outline-none focus:border-blue-500"
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
                  className="mt-3 text-xs text-blue-400 transition hover:text-blue-300"
                >
                  Clear all filters
                </button>
              )}

            </div>

            {/* Alert Action Error */}
            {alertActionError && (
              <div className="m-6 rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-400">
                {alertActionError}
              </div>
            )}

            {/* Alert Analytics Refresh Error */}
            {alertAnalyticsError && (
              <div className="m-6 rounded-lg border border-yellow-500/30 bg-yellow-500/10 p-3 text-sm text-yellow-400">
                {alertAnalyticsError}
              </div>
            )}

            <div className="overflow-x-auto">

              <table className="w-full min-w-[900px] text-left text-sm">

                <thead className="bg-[#0d1422] text-xs uppercase text-gray-400">
                  <tr>
                    <th className="px-6 py-4">Alert ID</th>
                    <th className="px-6 py-4">Source IP</th>
                    <th className="px-6 py-4">Detection Type</th>
                    <th className="px-6 py-4">Severity</th>
                    <th className="px-6 py-4">Status</th>
                    <th className="px-6 py-4">Timestamp</th>
                    <th className="px-6 py-4">Actions</th>
                  </tr>
                </thead>

                <tbody className="divide-y divide-gray-800">

                  {filteredAlerts.map((alert) => (

                    <tr
                      key={alert.id}
                      className="transition-colors hover:bg-gray-800/40"
                    >

                      {/* Alert ID */}
                      <td className="px-6 py-4 font-medium text-gray-300">
                        #{alert.id}
                      </td>

                      {/* Source IP */}
                      <td className="whitespace-nowrap px-6 py-4 text-gray-300">
                        {alert.source_ip}
                      </td>

                      {/* Detection Type */}
                      <td className="px-6 py-4 text-gray-300 capitalize">
                        {String(alert.alert_type || '').replaceAll('_', ' ')}
                      </td>

                      {/* Severity */}
                      <td className="px-6 py-4">
                        <span
                          className={`rounded-md px-2 py-1 text-xs font-semibold ${
                            alert.severity === 'HIGH'
                              ? 'bg-red-500/10 text-red-400'
                              : alert.severity === 'MEDIUM'
                              ? 'bg-yellow-500/10 text-yellow-400'
                              : 'bg-green-500/10 text-green-400'
                          }`}
                        >
                          {alert.severity}
                        </span>
                      </td>

                      {/* Status */}
                      <td className="px-6 py-4">
                        <span
                          className={`rounded-md px-2 py-1 text-xs font-medium ${
                            alert.status === 'NEW'
                              ? 'bg-blue-500/10 text-blue-400'
                              : alert.status === 'ACKNOWLEDGED'
                              ? 'bg-yellow-500/10 text-yellow-400'
                              : 'bg-green-500/10 text-green-400'
                          }`}
                        >
                          {alert.status}
                        </span>
                      </td>

                      {/* Timestamp */}
                      <td className="whitespace-nowrap px-6 py-4 text-gray-400">
                        {new Date(`${alert.timestamp}Z`).toLocaleString()}
                      </td>

                      {/* Actions */}
                      <td className="px-6 py-4">

                        <div className="flex items-center gap-2">

                          {alert.status === 'NEW' && (
                            <button
                              onClick={() =>
                                updateAlertStatus(alert.id, 'ACKNOWLEDGED')
                              }
                              disabled={updatingAlertId === alert.id}
                              className="whitespace-nowrap rounded-md bg-yellow-500/10 px-3 py-2 text-xs font-medium text-yellow-400 transition hover:bg-yellow-500/20 disabled:cursor-not-allowed disabled:opacity-50"
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
                              className="whitespace-nowrap rounded-md bg-green-500/10 px-3 py-2 text-xs font-medium text-green-400 transition hover:bg-green-500/20 disabled:cursor-not-allowed disabled:opacity-50"
                            >
                              {updatingAlertId === alert.id
                                ? 'Updating...'
                                : 'Resolve'}
                            </button>
                          )}

                          {alert.status === 'RESOLVED' && (
                            <span className="text-xs text-green-400">
                              Completed
                            </span>
                          )}

                        </div>

                      </td>

                    </tr>

                  ))}

                  {filteredAlerts.length === 0 && (
                    <tr>
                      <td
                        colSpan="7"
                        className="px-6 py-8 text-center text-gray-500"
                      >
                        No alerts match your search or selected filters.
                      </td>
                    </tr>
                  )}

                </tbody>

              </table>

            </div>

            <div className="border-t border-gray-800 px-6 py-4 text-xs text-gray-500">
              Showing {filteredAlerts.length} of {alertData.length} security alerts
            </div>

          </div>

        </div>
      </main>
    </div>
  )
}

export default App