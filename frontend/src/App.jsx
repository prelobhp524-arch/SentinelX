import { useCallback, useEffect, useRef, useState } from 'react'
import api from './services/api'

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
  Bell,
  User,
  ChevronDown,
  Play,
  Square,
  RefreshCw,
} from 'lucide-react'

const SEVERITY_COLORS = {
  HIGH: '#ef4444',
  MEDIUM: '#f59e0b',
  LOW: '#22c55e',
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
    interface: 'Wi-Fi',
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
  const [updatingAlertId, setUpdatingAlertId] = useState(null)
  const [alertActionError, setAlertActionError] = useState('')

  // Alert search and filters
  const [alertSearch, setAlertSearch] = useState('')
  const [severityFilter, setSeverityFilter] = useState('ALL')
  const [trafficDirectionFilter, setTrafficDirectionFilter] = useState('ALL')
  const [trafficProtocolFilter, setTrafficProtocolFilter] = useState('ALL')
  const [statusFilter, setStatusFilter] = useState('ALL')

  // WebSocket connection management
  const socketRef = useRef(null)
  const reconnectTimerRef = useRef(null)
  const reconnectAttemptsRef = useRef(0)
  const shouldReconnectRef = useRef(true)

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

  // Fetch available network interfaces
  const fetchInterfaces = useCallback(async (activeInterface) => {
    try {
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
      await fetchInterfaces(status?.interface)
    }

    initializeCapture()

    const interval = setInterval(fetchCaptureStatus, 5000)

    return () => clearInterval(interval)
  }, [fetchCaptureStatus, fetchInterfaces])
  // Update alert status through the backend API
  const updateAlertStatus = async (alertId, newStatus) => {
    try {
      setUpdatingAlertId(alertId)
      setAlertActionError('')

      const response = await api.patch(
        `/api/alerts/${alertId}/status`,
        {
          status: newStatus,
        }
      )

      const updatedAlert = response.data.data

      setAlertData((previousAlerts) =>
        previousAlerts.map((alert) =>
          alert.id === alertId ? updatedAlert : alert
        )
      )

      // Refresh analytics after changing alert status
      const [summaryResponse, severityResponse] = await Promise.all([
        api.get('/api/analytics/summary'),
        api.get('/api/analytics/alerts-by-severity'),
      ])

      setStats(summaryResponse.data)
      setAlertSeverityData(severityResponse.data)

    } catch (error) {
      console.error('Alert update error:', error)

      setAlertActionError(
        error.response?.data?.detail ||
        'Unable to update alert status. Please try again.'
      )

    } finally {
      setUpdatingAlertId(null)
    }
  }

  // Fetch dashboard data
  useEffect(() => {
    let isMounted = true

    const fetchDashboard = async () => {
      try {
        const [
          statsResponse,
          protocolResponse,
          alertsResponse,
          topIPsResponse,
          trafficResponse,
          alertsListResponse,
        ] = await Promise.all([
          api.get('/api/analytics/summary'),
          api.get('/api/analytics/traffic-by-protocol'),
          api.get('/api/analytics/alerts-by-severity'),
          api.get('/api/analytics/top-source-ips?limit=5'),
          api.get('/api/traffic/'),
          api.get('/api/alerts/'),
        ])

        if (!isMounted) return

        setStats(statsResponse.data)
        setProtocolData(protocolResponse.data)
        setAlertSeverityData(alertsResponse.data)
        setTopSourceIPs(topIPsResponse.data)
        setTrafficData(trafficResponse.data)

        // Do not overwrite alerts while a status update is happening
        if (updatingAlertId === null) {
          setAlertData(alertsListResponse.data)
        }

        setApiError('')

      } catch (error) {
        console.error('Dashboard API error:', error)

        if (isMounted) {
          setApiError('Unable to fetch dashboard data')
        }

      } finally {
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
        setTrafficData((previousTraffic) => {
          const remainingTraffic = previousTraffic.filter(
            (traffic) => traffic.id !== data.id
          )

          return [data, ...remainingTraffic]
        })

        return
      }

      if (event.type === 'alert.created') {
        setAlertData((previousAlerts) => {
          const remainingAlerts = previousAlerts.filter(
            (alert) => alert.id !== data.id
          )

          return [data, ...remainingAlerts]
        })

        return
      }

      if (event.type === 'alert.updated') {
        setAlertData((previousAlerts) => {
          const alertExists = previousAlerts.some(
            (alert) => alert.id === data.id
          )

          if (!alertExists) {
            return [data, ...previousAlerts]
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

      const socket = new WebSocket('ws://127.0.0.1:8000/ws')
      socketRef.current = socket

      socket.onopen = () => {
        reconnectAttemptsRef.current = 0
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

  // Filter network traffic by direction and protocol
const filteredTraffic = trafficData.filter((traffic) => {
  const matchesDirection =
    trafficDirectionFilter === 'ALL' ||
    traffic.direction === trafficDirectionFilter

  const matchesProtocol =
    trafficProtocolFilter === 'ALL' ||
    traffic.protocol === trafficProtocolFilter

  return matchesDirection && matchesProtocol
})
  // Filter alerts based on search, severity, and status
  const filteredAlerts = alertData.filter((alert) => {
    const searchValue = alertSearch.toLowerCase().trim()

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

  return (
    <div className="min-h-screen bg-[#080d18] text-gray-200">

      {/* Sidebar */}
      <aside className="fixed left-0 top-0 h-screen w-64 border-r border-gray-800 bg-[#0d1422] p-6">

        <div className="mb-10 flex items-center gap-3">
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

        <p className="mb-4 text-xs font-semibold uppercase tracking-wider text-gray-500">
          Main Menu
        </p>

        <nav className="space-y-2">
          <button className="flex w-full items-center gap-3 rounded-lg bg-blue-600/15 px-4 py-3 text-left text-blue-400">
            <LayoutDashboard size={19} />
            Dashboard
          </button>

          <button className="flex w-full items-center gap-3 rounded-lg px-4 py-3 text-left text-gray-400 hover:bg-gray-800 hover:text-white">
            <Activity size={19} />
            Network Traffic
          </button>

          <button className="flex w-full items-center gap-3 rounded-lg px-4 py-3 text-left text-gray-400 hover:bg-gray-800 hover:text-white">
            <AlertTriangle size={19} />
            Security Alerts
          </button>

          <button className="flex w-full items-center gap-3 rounded-lg px-4 py-3 text-left text-gray-400 hover:bg-gray-800 hover:text-white">
            <Network size={19} />
            IP Monitoring
          </button>
        </nav>

        <div className="absolute bottom-6 left-6 right-6">
          <button className="flex w-full items-center gap-3 rounded-lg px-4 py-3 text-gray-400 hover:bg-gray-800 hover:text-white">
            <Settings size={19} />
            Settings
          </button>
        </div>
      </aside>

      {/* Main Content */}
      <main className="ml-64 min-h-screen">

        {/* Top Navigation */}
        <header className="flex h-20 items-center justify-between border-b border-gray-800 px-8">

          <div>
            <h2 className="text-xl font-semibold text-white">
              Security Dashboard
            </h2>

            <p className="text-sm text-gray-500">
              Monitor your network security in real time
            </p>
          </div>

          <div className="flex items-center gap-5">
            <button className="text-gray-400 hover:text-white">
              <Search size={20} />
            </button>

            <button className="relative text-gray-400 hover:text-white">
              <Bell size={20} />
              <span className="absolute -right-1 -top-1 h-2 w-2 rounded-full bg-red-500"></span>
            </button>

            <div className="flex items-center gap-2 border-l border-gray-800 pl-5">
              <div className="rounded-full bg-gray-700 p-2">
                <User size={18} />
              </div>

              <span className="text-sm text-gray-300">
                Administrator
              </span>

              <ChevronDown size={15} className="text-gray-500" />
            </div>
          </div>
        </header>

        {/* Dashboard Body */}
        <div className="p-8">

          {/* Overview */}
          <div className="mb-8 flex items-center justify-between">
            <div>
              <h3 className="text-2xl font-bold text-white">
                Overview
              </h3>

              <p className="mt-1 text-sm text-gray-500">
                Your network security at a glance
              </p>
            </div>

            <div className="rounded-lg border border-green-500/30 bg-green-500/10 px-4 py-2 text-sm text-green-400">
              ● System Online
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

            </div>

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

          </div>

          {/* Recent Network Traffic */}
          <div className="mt-8 overflow-hidden rounded-xl border border-gray-800 bg-[#111b2b]">

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
              <table className="w-full text-left text-sm">

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
          <div className="mt-8 overflow-hidden rounded-xl border border-gray-800 bg-[#111b2b]">

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
                  {alertData.filter((alert) => alert.status !== 'RESOLVED').length} Active Alerts
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

            <div className="overflow-x-auto">

              <table className="w-full text-left text-sm">

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