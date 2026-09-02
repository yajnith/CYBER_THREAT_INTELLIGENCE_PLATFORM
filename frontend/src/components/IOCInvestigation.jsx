import { useState } from 'react'

function IOCInvestigation() {
  const [search, setSearch] = useState('')
  const [ioc, setIoc] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const investigate = async () => {
    if (!search.trim()) {
      setError('Please enter an IOC')
      setIoc(null)
      return
    }

    setLoading(true)
    setError('')
    setIoc(null)

    try {
      // Search all stored IOCs instead of limiting the search
      // to manual_test sources.
      const searchResponse = await fetch(
        'http://127.0.0.1:8000/api/v1/iocs/search'
      )

      if (!searchResponse.ok) {
        throw new Error('Failed to search IOCs')
      }

      const searchResult = await searchResponse.json()

      const match = searchResult.data.find(
        (item) =>
          item.value.toLowerCase() ===
          search.trim().toLowerCase()
      )

      if (!match) {
        setError('IOC not found')
        return
      }

      // The backend now performs risk scoring and enrichment.
      const detailResponse = await fetch(
        `http://127.0.0.1:8000/api/v1/iocs/${match.id}`
      )

      if (!detailResponse.ok) {
        throw new Error('Failed to retrieve IOC intelligence')
      }

      const detailResult = await detailResponse.json()

      setIoc(detailResult)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  const record = ioc?.ioc
  const enrichment = ioc?.enrichment

  return (
    <section className="investigation">
      <div className="investigation-header">
        <p className="eyebrow">
          ANALYST WORKSPACE
        </p>

        <h2>IOC Investigation</h2>

        <p>
          Search and investigate stored indicators.
        </p>
      </div>

      <div className="investigation-search">
        <input
          type="text"
          value={search}
          onChange={(event) =>
            setSearch(event.target.value)
          }
          onKeyDown={(event) => {
            if (event.key === 'Enter') {
              investigate()
            }
          }}
          placeholder="Enter an IOC..."
        />

        <button
          type="button"
          onClick={investigate}
          disabled={loading}
        >
          {loading
            ? 'Investigating...'
            : 'Investigate'}
        </button>
      </div>

      {error && (
        <div className="error-banner">
          {error}
        </div>
      )}

      {record && (
        <div className="investigation-card">
          <div className="ioc-title">
            <div>
              <span className="stat-label">
                Indicator
              </span>

              <h3>{record.value}</h3>
            </div>

            <span
              className={`severity ${record.severity}`}
            >
              {record.severity}
            </span>
          </div>

          <div className="investigation-grid">
            <div>
              <span>Type</span>
              <strong>
                {record.indicator_type}
              </strong>
            </div>

            <div>
              <span>Confidence</span>
              <strong>
                {record.confidence}%
              </strong>
            </div>

            <div>
              <span>Source</span>
              <strong>
                {record.source}
              </strong>
            </div>

            <div>
              <span>Threat Type</span>
              <strong>
                {record.threat_type || 'Unknown'}
              </strong>
            </div>

            <div>
              <span>First Seen</span>
              <strong>
                {new Date(
                  record.first_seen
                ).toLocaleString()}
              </strong>
            </div>

            <div>
              <span>Last Seen</span>
              <strong>
                {new Date(
                  record.last_seen
                ).toLocaleString()}
              </strong>
            </div>
          </div>

          <div className="risk-result">
            <div>
              <span>Calculated Risk Score</span>

              <strong>
                {ioc.risk_score}/100
              </strong>
            </div>

            <div>
              <span>Risk Level</span>

              <strong
                className={`risk-level ${ioc.risk_level}`}
              >
                {ioc.risk_level}
              </strong>
            </div>
          </div>

          <div className="enrichment-section">
            <h3>Enrichment</h3>

            <div className="enrichment-grid">
              <div>
                <span>Normalized Value</span>

                <strong>
                  {record.normalized_value}
                </strong>
              </div>

              <div>
                <span>Tags</span>

                <strong>
                  {record.tags?.join(', ') || 'None'}
                </strong>
              </div>

              <div>
                <span>Value Length</span>

                <strong>
                  {enrichment?.length ?? '—'}
                </strong>
              </div>

              <div>
                <span>Special Characters</span>

                <strong>
                  {enrichment?.has_special_characters
                    ? 'Yes'
                    : 'No'}
                </strong>
              </div>
            </div>
          </div>
        </div>
      )}
    </section>
  )
}

export default IOCInvestigation