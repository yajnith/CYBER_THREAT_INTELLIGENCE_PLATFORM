import { useState } from 'react'

function IOCSearch() {
  const [filters, setFilters] = useState({
    indicator_type: '',
    severity: '',
    source: '',
    threat_type: '',
  })

  const [results, setResults] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const handleChange = (event) => {
    const { name, value } = event.target

    setFilters((previous) => ({
      ...previous,
      [name]: value,
    }))
  }

  const handleSearch = async (event) => {
    event.preventDefault()

    setLoading(true)
    setError('')

    try {
      const params = new URLSearchParams()

      Object.entries(filters).forEach(([key, value]) => {
        if (value.trim()) {
          params.append(key, value.trim())
        }
      })

      const query = params.toString()

      const response = await fetch(
        `http://127.0.0.1:8000/api/v1/iocs/search${
          query ? `?${query}` : ''
        }`
      )

      if (!response.ok) {
        throw new Error('Failed to search IOCs')
      }

      const data = await response.json()

      setResults(data.data || [])
    } catch (err) {
      setError(err.message)
      setResults([])
    } finally {
      setLoading(false)
    }
  }

  return (
    <section className="investigation">

      <div className="investigation-header">
        <p className="eyebrow">
          ANALYST WORKSPACE
        </p>

        <h2>IOC Search</h2>

        <p>
          Search and filter stored indicators across the CTIP database.
        </p>
      </div>

      <div className="investigation-card">

        <form onSubmit={handleSearch}>

          <div className="investigation-grid">

            <div>
              <span>Indicator Type</span>

              <select
                name="indicator_type"
                value={filters.indicator_type}
                onChange={handleChange}
              >
                <option value="">All Types</option>
                <option value="domain">Domain</option>
                <option value="ipv4">IPv4</option>
                <option value="ipv6">IPv6</option>
                <option value="url">URL</option>
                <option value="hash_md5">MD5</option>
                <option value="hash_sha1">SHA-1</option>
                <option value="hash_sha256">SHA-256</option>
                <option value="cve">CVE</option>
                <option value="email">Email</option>
              </select>
            </div>

            <div>
              <span>Severity</span>

              <select
                name="severity"
                value={filters.severity}
                onChange={handleChange}
              >
                <option value="">All Severities</option>
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
              </select>
            </div>

            <div>
              <span>Source</span>

              <input
                type="text"
                name="source"
                value={filters.source}
                onChange={handleChange}
                placeholder="e.g. manual_test"
              />
            </div>

            <div>
              <span>Threat Type</span>

              <input
                type="text"
                name="threat_type"
                value={filters.threat_type}
                onChange={handleChange}
                placeholder="e.g. phishing"
              />
            </div>

          </div>

          <button
            type="submit"
            className="investigate-button"
            disabled={loading}
          >
            {loading ? 'Searching...' : 'Search IOCs'}
          </button>

        </form>

        {error && (
          <div className="risk-result">
            <h3>Search failed</h3>
            <p>{error}</p>
          </div>
        )}

      </div>

      <div className="investigation-card">

        <div className="panel-header">
          <div>
            <h2>Search Results</h2>

            <p>
              {results.length} IOC
              {results.length !== 1 ? 's' : ''} found
            </p>
          </div>
        </div>

        {loading ? (
          <div className="empty-state">
            Searching threat intelligence...
          </div>
        ) : results.length === 0 ? (
          <div className="empty-state">
            No IOCs found. Try changing the filters.
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
                  <th>Threat Type</th>
                  <th>Last Seen</th>
                </tr>
              </thead>

              <tbody>

                {results.map((ioc) => (
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
                      {ioc.threat_type || '—'}
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

      </div>

    </section>
  )
}

export default IOCSearch