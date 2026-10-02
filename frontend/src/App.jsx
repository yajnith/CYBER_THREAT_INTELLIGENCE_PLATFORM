import { useCallback, useEffect, useMemo, useState } from 'react'

import IOCInvestigation from './components/IOCInvestigation'

import IOCSubmission from './components/IOCSubmission'

import IOCSearch from './components/IOCSearch'

import CTIFeedIngestion from './components/CTIFeedIngestion'

import ResearchOverview from './components/ResearchOverview'

import BarChart from './components/BarChart'

import './App.css'

function App() {
  const [authenticated, setAuthenticated] = useState(() => {
    try {
      return window.localStorage.getItem('ctip_authenticated') === 'true'
    } catch {
      return false
    }
  })

  const [userMenuOpen, setUserMenuOpen] = useState(false)

  const [userName, setUserName] = useState(() => {
    try {
      return window.localStorage.getItem('ctip_user_name') || 'Analyst'
    } catch {
      return 'Analyst'
    }
  })

  const [view, setView] = useState('dashboard')

  const [iocs, setIocs] = useState([])

  const [urlhausSummary, setUrlhausSummary] = useState(null)

  const [urlhausError, setUrlhausError] = useState('')

  const [sourceCount, setSourceCount] = useState(0)

  const [loading, setLoading] = useState(true)

  const [error, setError] = useState('')

  const [apiStatus, setApiStatus] = useState('checking')

  const handleLogin = useCallback((name) => {
    const displayName = name.trim() || 'Analyst'

    try {
      window.localStorage.setItem('ctip_authenticated', 'true')
      window.localStorage.setItem('ctip_user_name', displayName)
    } catch {
      // Continue with in-memory authentication if storage is unavailable.
    }

    setUserName(displayName)
    setAuthenticated(true)
    setView('dashboard')
  }, [])

  const handleLogout = useCallback(() => {
    try {
      window.localStorage.removeItem('ctip_authenticated')
      window.localStorage.removeItem('ctip_user_name')
    } catch {
      // Continue with in-memory logout if storage is unavailable.
    }

    setUserMenuOpen(false)
    setAuthenticated(false)
    setView('dashboard')
  }, [])

  const refreshDashboard = useCallback(() => {

    setLoading(true)

    setError('')

    setApiStatus('checking')

    return fetch('http://127.0.0.1:8000/api/v1/iocs')

      .then((response) => {

        if (!response.ok) {

          throw new Error('Failed to fetch IOCs')

        }

        return response.json()

      })

      .then((result) => {

        if (!result || !Array.isArray(result.data)) {

          throw new Error('CTIP API returned an invalid dashboard response')

        }

        setIocs(result.data)

        setSourceCount(result.source_count || 0)

        setApiStatus('connected')

        setLoading(false)

      })

      .catch((err) => {

        setError(err.message)

        setApiStatus('unavailable')

        setLoading(false)

      })

  }, [])

  useEffect(() => {

    refreshDashboard()

  }, [refreshDashboard])

  useEffect(() => {

    fetch('http://127.0.0.1:8000/api/v1/research/urlhaus/summary')

      .then((response) => {

        if (!response.ok) throw new Error(`URLhaus research API returned ${response.status}`)

        return response.json()

      })

      .then((summary) => setUrlhausSummary(summary))

      .catch((requestError) => setUrlhausError(requestError.message))

  }, [])

  const statistics = useMemo(() => {

    const urlhausCount = iocs.filter(

      (ioc) => (ioc.sources || []).includes('URLhaus')

    ).length

    const observations = iocs.reduce((total, ioc) => total + (Number(ioc.observation_count) || 0), 0)

    const typeCounts = countBy(iocs, (ioc) => ioc.indicator_type || 'unknown')

    const riskCounts = countBy(iocs, (ioc) => ioc.risk_level || 'unknown')

    const sourceCounts = {}

    iocs.forEach((ioc) => {

      const uniqueSources = new Set(ioc.sources || [])

      uniqueSources.forEach((source) => {

        sourceCounts[source] = (sourceCounts[source] || 0) + 1

      })

    })

    return {

      total: iocs.length,

      sources: sourceCount,

      urlhausCount,

      observations,

      typeDistribution: Object.entries(typeCounts).map(([label, value]) => ({ label, value })),

      riskDistribution: ['critical', 'high', 'medium', 'low', 'unknown']

        .filter((level) => riskCounts[level] !== undefined)

        .map((label) => ({ label, value: riskCounts[label] || 0 })),

      sourceDistribution: Object.entries(sourceCounts)

        .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))

        .map(([label, value]) => ({ label, value })),

    }

  }, [iocs, sourceCount])

  if (!authenticated) {
    return <LoginPage onLogin={handleLogin} />
  }

  return (

    <div className="dashboard">

      <aside className="sidebar">

        <div className="brand">

          <div className="brand-icon">C</div>

          <div>

            <h2>CTIP</h2>

            <span>Threat Intelligence</span>

          </div>

        </div>

        <div className="sidebar-section-label">Operations</div>

        <nav>

          <div

            className={`nav-item ${

              view === 'dashboard' ? 'active' : ''

            }`}

            onClick={() => setView('dashboard')}

          >

            <span>▣</span>

            Dashboard

          </div>

          <div

            className={`nav-item ${

              view === 'investigation' ? 'active' : ''

            }`}

            onClick={() => setView('investigation')}

          >

            <span>◈</span>

            IOC Intelligence

          </div>

          <div

            className={`nav-item ${

              view === 'submission' ? 'active' : ''

            }`}

            onClick={() => setView('submission')}

          >

            <span>＋</span>

            Submit IOC

          </div>

          <div

            className={`nav-item ${

              view === 'search' ? 'active' : ''

            }`}

            onClick={() => setView('search')}

          >

            <span>⌕</span>

            Search

          </div>

          <div

            className={`nav-item ${

              view === 'ingestion' ? 'active' : ''

            }`}

            onClick={() => setView('ingestion')}

          >

            <span>⇧</span>

            CTI Feed Ingestion

          </div>

          <div className="sidebar-section-label sidebar-section-label-research">Research</div>

          <div

            className={`nav-item ${view === 'research' ? 'active' : ''}`}

            onClick={() => setView('research')}

          >

            <span>⌁</span>

            Research &amp; AI

          </div>

        </nav>

        <div className="sidebar-footer">
          <div
  className="sidebar-footer"
  style={{
    display: 'block',
    width: '100%',
    boxSizing: 'border-box',
  }}
>
  <div
    style={{
      width: '100%',
      display: 'flex',
      flexDirection: 'column',
      gap: '10px',
      boxSizing: 'border-box',
    }}
  >
    {/* API STATUS */}
    <div
      className="api-status-card"
      style={{
        width: '100%',
        boxSizing: 'border-box',
        display: 'flex',
        alignItems: 'center',
      }}
    >
      <span className={`status-dot ${apiStatus}`}></span>

      <div style={{ minWidth: 0 }}>
        <strong>
          {apiStatus === 'connected'
            ? 'API Connected'
            : apiStatus === 'unavailable'
              ? 'API Unavailable'
              : 'Checking API'}
        </strong>

        <span>CTIP backend status</span>
      </div>
    </div>

    {/* USER ACCOUNT */}
    <div
      className="user-area"
      style={{
        position: 'relative',
        width: '100%',
        boxSizing: 'border-box',
      }}
    >
      {userMenuOpen && (
        <div
          className="user-menu"
          style={{
            position: 'absolute',
            right: 0,
            bottom: 'calc(100% + 10px)',
            zIndex: 9999,
          }}
        >
          <div className="user-menu-header">
            <div className="user-avatar">
              {userName.charAt(0).toUpperCase()}
            </div>

            <div>
              <strong>{userName}</strong>
              <span>CTIP Analyst</span>
            </div>
          </div>

          <div className="user-menu-divider"></div>

          <button
            type="button"
            className="user-menu-item"
            onClick={() => setUserMenuOpen(false)}
          >
            <span>◉</span>
            Account
          </button>

          <button
            type="button"
            className="user-menu-item"
            onClick={() => setUserMenuOpen(false)}
          >
            <span>⚙</span>
            Settings
            <small>Coming next</small>
          </button>

          <div className="user-menu-divider"></div>

          <button
            type="button"
            className="user-menu-item logout-item"
            onClick={handleLogout}
          >
            <span>↪</span>
            Sign out
          </button>
        </div>
      )}

      <button
        type="button"
        className={`user-card ${userMenuOpen ? 'open' : ''}`}
        onClick={() => setUserMenuOpen((open) => !open)}
        aria-expanded={userMenuOpen}
        style={{
          width: '100%',
          boxSizing: 'border-box',
        }}
      >
        <div className="user-avatar">
          {userName.charAt(0).toUpperCase()}
        </div>

        <div className="user-card-copy">
          <strong>{userName}</strong>
          <span>Analyst</span>
        </div>

        <span className="user-chevron">
          {userMenuOpen ? '⌃' : '⌄'}
        </span>
      </button>
    </div>
  </div>
</div>
        </div>

      </aside>

      <main className="main-content">

        {view === 'dashboard' ? (

          <>

            <header className="topbar">

              <div>

                <p className="eyebrow">

                  CYBER THREAT INTELLIGENCE PLATFORM

                </p>

                <h1>Threat Overview</h1>

                <p className="subtitle">

                  Monitor, analyze and investigate Indicators of Compromise.

                </p>

              </div>

              <div className="live-status">

                <span className="status-dot"></span>

                Stored CTIP Data

              </div>

            </header>

            {error && (

              <div className="error-banner">

                Unable to connect to CTIP API: {error}

              </div>

            )}

            <section className="dataset-provenance" aria-label="Real URLhaus research dataset">

              <div>

                <span className="dataset-provenance-label">Real URLhaus CTI Dataset</span>

                <strong>{urlhausSummary ? `${urlhausSummary.record_count.toLocaleString()} research records` : 'Loading research dataset summary'}</strong>

              </div>

              <p>

                Complete normalized research dataset. The operational IOC database is a separate

                demonstration subset used for ingestion, observations, investigation, and deterministic risk scoring.

              </p>

            </section>

            {urlhausError && <div className="error-banner">Unable to load URLhaus research analytics: {urlhausError}</div>}

            <section className="stats-grid">

              <DatasetStat label="Total CTI Records" value={urlhausSummary?.record_count} />

              <DatasetStat label="URLhaus Records" value={urlhausSummary?.record_count} />

              <DatasetStat label="Online" value={urlhausSummary?.url_status_distribution?.online} />

              <DatasetStat label="Offline" value={urlhausSummary?.url_status_distribution?.offline} />

              <DatasetStat label="Reporters" value={urlhausSummary?.unique_reporter_count} />

              <DatasetStat label="Research Features" value={urlhausSummary?.feature_count} />

            </section>

            {urlhausSummary && (

              <section className="dashboard-research-grid">

                <DatasetChart title="URLhaus Threat Distribution" items={chartItems(urlhausSummary.threat_distribution)} color="amber" />

                <DatasetChart title="URLhaus Status Distribution" items={chartItems(urlhausSummary.url_status_distribution)} color="green" />

                <DatasetChart title="Top Tags" items={urlhausSummary.top_tags} color="purple" />

                <DatasetChart title="Top Reporters" items={urlhausSummary.top_reporters} color="blue" />

                <div className="panel dashboard-temporal-panel">

                  <div className="panel-header"><div><h2>Temporal Activity</h2><p>URLhaus date_added records by month</p></div></div>

                  <BarChart items={urlhausSummary.temporal_distribution_by_month} label="URLhaus records by month from date_added" color="green" axisLabel="records" />

                  <p className="dashboard-data-note">Date range: {urlhausSummary.date_range?.first_date_added || '—'} to {urlhausSummary.date_range?.last_date_added || '—'}</p>

                </div>

              </section>

            )}

            <section className="dataset-provenance operational-provenance" aria-label="Operational CTIP demonstration dataset">

              <div>

                <span className="dataset-provenance-label">Operational CTIP Demo / Investigation Dataset</span>

                <strong>{loading ? 'Loading operational records' : `${statistics.urlhausCount.toLocaleString()} URLhaus records · ${statistics.total.toLocaleString()} total IOCs`}</strong>

              </div>

              <p>This smaller PostgreSQL dataset powers feed ingestion, normalization, deduplication, observations, source correlation, investigation, and the deterministic production risk engine.</p>

            </section>

            <section className="stats-grid operational-stats-grid">

              <DatasetStat label="Operational IOCs" value={loading ? null : statistics.total} />

              <DatasetStat label="Stored Observations" value={loading ? null : statistics.observations} />

              <DatasetStat label="Observed Sources" value={loading ? null : statistics.sources} />

            </section>

            <section className="content-grid">

              <div className="panel">

                <div className="panel-header">

                  <div>

                    <h2>Risk Distribution</h2>

                    <p>

                      Current deterministic risk profile

                    </p>

                  </div>

                </div>

                <BarChart

                  items={statistics.riskDistribution}

                  label="Stored IOC count by deterministic risk level"

                  color="amber"

                  axisLabel="IOCs"

                />

              </div>

              <div className="panel">

                <div className="panel-header">

                  <div>

                    <h2>IOC Types</h2>

                    <p>

                      Indicator distribution

                    </p>

                  </div>

                </div>

                <BarChart

                  items={statistics.typeDistribution}

                  label="Stored IOC count by indicator type"

                  color="blue"

                  axisLabel="IOCs"

                />

              </div>

            </section>

            <section className="panel dashboard-source-panel">

              <div className="panel-header">

                <div><h2>IOC Count by Source</h2><p>Distinct stored IOCs associated with each observed source</p></div>

              </div>

              <BarChart

                items={statistics.sourceDistribution}

                label="Stored IOC count by observation source"

                color="green"

                axisLabel="IOCs"

              />

              <p className="dashboard-data-note">Operational view of the current CTIP database. It updates from the IOC API response.</p>

            </section>

            <section className="panel table-panel">

              <div className="panel-header">

                <div>

                  <h2>Recent Indicators</h2>

                  <p>

                    Latest indicators stored in PostgreSQL

                  </p>

                </div>

                <span className="record-count">

                  {iocs.length} records

                </span>

              </div>

              {loading ? (

                <div className="empty-state">

                  Loading threat intelligence...

                </div>

              ) : iocs.length === 0 ? (

                <div className="empty-state">

                  No IOCs found.

                </div>

              ) : (

                <div className="table-wrapper">

                  <table>

                    <thead>

                      <tr>

                        <th>Indicator</th>

                        <th>Type</th>

                        <th>Risk Level</th>

                        <th>Risk Score</th>

                        <th>Confidence</th>

                        <th>Observed Sources</th>

                        <th>Last Seen</th>

                      </tr>

                    </thead>

                    <tbody>

                      {iocs.map((ioc) => (

                        <tr key={ioc.id}>

                          <td className="indicator">

                            {ioc.value}

                          </td>

                          <td>

                            <span className="type-pill">

                              {ioc.indicator_type}

                            </span>

                          </td>

                          <td>

                            <span

                              className={`severity ${ioc.risk_level}`}

                            >

                              {ioc.risk_level}

                            </span>

                          </td>

                          <td>{ioc.risk_score}/100</td>

                          <td>

                            {ioc.confidence}%

                          </td>

                          <td>

                            {(ioc.sources || []).join(', ') || '—'}

                          </td>

                          <td>

                            {new Date(

                              ioc.last_seen

                            ).toLocaleString()}

                          </td>

                        </tr>

                      ))}

                    </tbody>

                  </table>

                </div>

              )}

            </section>

          </>

        ) : view === 'investigation' ? (

          <IOCInvestigation onNavigateResearch={() => setView('research')} />

        ) : view === 'submission' ? (

          <IOCSubmission onSubmitted={refreshDashboard} />

        ) : view === 'search' ? (

          <IOCSearch />

        ) : view === 'ingestion' ? (

          <CTIFeedIngestion onIngested={refreshDashboard} />

        ) : view === 'research' ? (

          <ResearchOverview />

        ) : (

          <IOCSearch />

        )}

      </main>

    </div>

  )

}

function LoginPage({ onLogin }) {

  const [name, setName] = useState('')

  const [password, setPassword] = useState('')

  const [showPassword, setShowPassword] = useState(false)

  const [error, setError] = useState('')

  const submit = (event) => {

    event.preventDefault()

    if (!name.trim() || !password.trim()) {

      setError('Enter your analyst name and password to continue.')

      return

    }

    setError('')

    onLogin(name)

  }

  return (

    <div className="login-shell">

      <div className="login-grid-glow"></div>

      <div className="login-panel">

        <div className="login-brand">

          <div className="login-brand-mark">C</div>

          <div>

            <strong>CTIP</strong>

            <span>Threat Intelligence Platform</span>

          </div>

        </div>

        <div className="login-heading">

          <span className="login-eyebrow">SECURE ANALYST CONSOLE</span>

          <h1>Welcome back.</h1>

          <p>Sign in to access your cyber threat intelligence workspace.</p>

        </div>

        <form className="login-form" onSubmit={submit}>

          <label>

            <span>Analyst name</span>

            <div className="login-input-wrap">

              <span className="login-input-icon">◉</span>

              <input

                type="text"

                value={name}

                onChange={(event) => setName(event.target.value)}

                placeholder="Enter your name"

                autoComplete="username"

                autoFocus

              />

            </div>

          </label>

          <label>

            <span>Password</span>

            <div className="login-input-wrap">

              <span className="login-input-icon">◆</span>

              <input

                type={showPassword ? 'text' : 'password'}

                value={password}

                onChange={(event) => setPassword(event.target.value)}

                placeholder="Enter your password"

                autoComplete="current-password"

              />

              <button

                type="button"

                className="password-toggle"

                onClick={() => setShowPassword((visible) => !visible)}

                aria-label={showPassword ? 'Hide password' : 'Show password'}

              >

                {showPassword ? 'Hide' : 'Show'}

              </button>

            </div>

          </label>

          {error && <div className="login-error">{error}</div>}

          <button type="submit" className="login-submit">

            <span>Enter analyst console</span>

            <span>→</span>

          </button>

        </form>

        <div className="login-note">

          <span className="status-dot connected"></span>

          <span>Frontend demo authentication · CTIP backend protected separately</span>

        </div>

      </div>

      <div className="login-footer">

        <span>CTIP</span>

        <span>Cyber Threat Intelligence Platform</span>

        <span>Analyst Workspace</span>

      </div>

    </div>

  )

}

function countBy(items, getKey) {

  return items.reduce((counts, item) => {

    const key = getKey(item)

    counts[key] = (counts[key] || 0) + 1

    return counts

  }, {})

}

function DatasetStat({ label, value }) {

  return (

    <div className="stat-card">

      <span className="stat-label">{label}</span>

      <strong>{typeof value === 'number' ? value.toLocaleString() : '—'}</strong>

      <span className="stat-description">{typeof value === 'number' ? 'From current CTIP data' : 'Research API loading'}</span>

    </div>

  )

}

function DatasetChart({ title, items, color }) {

  return (

    <div className="panel">

      <div className="panel-header"><div><h2>{title}</h2><p>Complete normalized URLhaus research dataset</p></div></div>

      <BarChart items={items || []} label={`${title} from normalized URLhaus dataset`} color={color} axisLabel="records" />

    </div>

  )

}

function chartItems(distribution) {

  if (!distribution || typeof distribution !== 'object') return []

  return Object.entries(distribution).map(([label, value]) => ({ label, value }))

}

export default App
