import { useEffect, useMemo, useState } from 'react'
import IOCInvestigation from './components/IOCInvestigation'
import './App.css'

function App() {
  const [view, setView] = useState('dashboard')
  const [iocs, setIocs] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    fetch('http://127.0.0.1:8000/api/v1/iocs')
      .then((response) => {
        if (!response.ok) {
          throw new Error('Failed to fetch IOCs')
        }

        return response.json()
      })
      .then((result) => {
        setIocs(result.data || [])
        setLoading(false)
      })
      .catch((err) => {
        setError(err.message)
        setLoading(false)
      })
  }, [])

  const statistics = useMemo(() => {
    const highRisk = iocs.filter(
      (ioc) =>
        ioc.severity === 'high' ||
        ioc.severity === 'critical'
    ).length

    const critical = iocs.filter(
      (ioc) => ioc.severity === 'critical'
    ).length

    const sources = new Set(
      iocs.map((ioc) => ioc.source)
    ).size

    const domains = iocs.filter(
      (ioc) => ioc.indicator_type === 'domain'
    ).length

    return {
      total: iocs.length,
      highRisk,
      critical,
      sources,
      domains,
    }
  }, [iocs])

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
              view === 'search' ? 'active' : ''
            }`}
            onClick={() => setView('search')}
          >
            <span>⌕</span>
            Search
          </div>

          <div className="nav-item">
            <span>⚙</span>
            Settings
          </div>
        </nav>

        <div className="sidebar-footer">
          <span className="status-dot"></span>
          API Connected
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
                Live Intelligence
              </div>
            </header>

            {error && (
              <div className="error-banner">
                Unable to connect to CTIP API: {error}
              </div>
            )}

            <section className="stats-grid">
              <div className="stat-card">
                <span className="stat-label">
                  Total IOCs
                </span>

                <strong>
                  {loading ? '—' : statistics.total}
                </strong>

                <span className="stat-description">
                  Stored indicators
                </span>
              </div>

              <div className="stat-card">
                <span className="stat-label">
                  High Risk
                </span>

                <strong>
                  {loading ? '—' : statistics.highRisk}
                </strong>

                <span className="stat-description">
                  High + critical
                </span>
              </div>

              <div className="stat-card">
                <span className="stat-label">
                  Critical
                </span>

                <strong>
                  {loading ? '—' : statistics.critical}
                </strong>

                <span className="stat-description">
                  Immediate attention
                </span>
              </div>

              <div className="stat-card">
                <span className="stat-label">
                  Sources
                </span>

                <strong>
                  {loading ? '—' : statistics.sources}
                </strong>

                <span className="stat-description">
                  Intelligence sources
                </span>
              </div>
            </section>

            <section className="content-grid">
              <div className="panel">
                <div className="panel-header">
                  <div>
                    <h2>Risk Distribution</h2>

                    <p>
                      Current IOC severity profile
                    </p>
                  </div>
                </div>

                <div className="risk-list">
                  {[
                    'critical',
                    'high',
                    'medium',
                    'low',
                  ].map((level) => {
                    const count = iocs.filter(
                      (ioc) => ioc.severity === level
                    ).length

                    const percentage =
                      iocs.length > 0
                        ? Math.round(
                            (count / iocs.length) * 100
                          )
                        : 0

                    return (
                      <div
                        className="risk-row"
                        key={level}
                      >
                        <div
                          className={`risk-badge ${level}`}
                        >
                          {level}
                        </div>

                        <div className="risk-bar-container">
                          <div
                            className={`risk-bar ${level}`}
                            style={{
                              width: `${percentage}%`,
                            }}
                          ></div>
                        </div>

                        <strong>{count}</strong>
                      </div>
                    )
                  })}
                </div>
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

                <div className="type-summary">
                  <div className="type-number">
                    {statistics.domains}
                  </div>

                  <div>
                    <strong>Domains</strong>

                    <p>
                      Currently stored
                    </p>
                  </div>
                </div>

                <div className="type-list">
                  {Object.entries(
                    iocs.reduce((result, ioc) => {
                      result[ioc.indicator_type] =
                        (result[ioc.indicator_type] || 0) + 1

                      return result
                    }, {})
                  ).map(([type, count]) => (
                    <div
                      className="type-row"
                      key={type}
                    >
                      <span>{type}</span>

                      <strong>{count}</strong>
                    </div>
                  ))}
                </div>
              </div>
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
                        <th>Severity</th>
                        <th>Confidence</th>
                        <th>Source</th>
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
                              className={`severity ${ioc.severity}`}
                            >
                              {ioc.severity}
                            </span>
                          </td>

                          <td>
                            {ioc.confidence}%
                          </td>

                          <td>
                            {ioc.source}
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
          <IOCInvestigation />
        ) : (
          <IOCInvestigation />
        )}
      </main>
    </div>
  )
}

export default App