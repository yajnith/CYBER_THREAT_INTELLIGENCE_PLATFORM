import { useState } from 'react'

function IOCInvestigation({ onNavigateResearch }) {
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

      if (!Array.isArray(searchResult?.data)) {
        throw new Error('The CTIP API returned an invalid IOC search response.')
      }

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

      if (!detailResult?.ioc || typeof detailResult.risk_score !== 'number') {
        throw new Error('The CTIP API returned an incomplete IOC investigation response.')
      }

      setIoc(detailResult)
    } catch (err) {
      setError(err instanceof TypeError
        ? 'Could not reach the CTIP API. Check that the backend is running and try again.'
        : err.message)
    } finally {
      setLoading(false)
    }
  }

  const record = ioc?.ioc
  const enrichment = ioc?.enrichment
  const correlation = ioc?.correlation
  const riskExplanation = ioc?.risk_explanation
  const research = ioc?.research_context
  const attackContext = ioc?.attack_context
  const cveContext = ioc?.cve_context
  const recommendations = ioc?.mitigation_recommendations || []
  const observationCount = correlation?.observation_count ?? ioc?.observations?.length ?? 0

  return (
    <section className="investigation">
      <div className="investigation-header">
        <p className="eyebrow">
          OPERATIONAL CTIP
        </p>

        <h2>IOC Investigation</h2>

        <p>
          Investigate operational IOC evidence, enrichment, correlation and deterministic risk.
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
                {correlation?.sources?.join(', ') || 'No observations'}
              </strong>
            </div>

            <div>
              <span>Correlated Sources</span>
              <strong>{ioc.source_count ?? 0}</strong>
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

          <div className="enrichment-section">
            <h3>Rule-based ATT&amp;CK-style threat context</h3>
            <p>This maps observed threat types and tags to possible tactic categories. It is not a complete ATT&amp;CK integration and provides no inferred technique IDs.</p>
            {attackContext?.tactics?.length ? (
              <div className="enrichment-grid">
                {attackContext.tactics.map((tactic) => <div key={tactic}><span>Possible tactic</span><strong>{tactic}</strong></div>)}
              </div>
            ) : <p>No known tactic mapping for the available threat context.</p>}
          </div>

          {cveContext && (
            <div className="enrichment-section">
              <h3>Local CVE identifier context</h3>
              <div className="enrichment-grid">
                <div><span>CVE</span><strong>{cveContext.cve}</strong></div>
                <div><span>Identifier format</span><strong>{cveContext.identifier_valid ? 'Valid format' : 'Unrecognized format'}</strong></div>
                <div><span>Year</span><strong>{cveContext.year ?? 'Unavailable'}</strong></div>
                <div><span>Numeric identifier</span><strong>{cveContext.numeric_identifier_text ?? 'Unavailable'}</strong></div>
                <div><span>CVSS</span><strong>{cveContext.cvss_available ? cveContext.cvss_score : 'Unavailable; no CVE database queried'}</strong></div>
              </div>
            </div>
          )}

          <div className="enrichment-section">
            <h3>Analyst mitigation recommendations</h3>
            <p>Deterministic guidance based on recorded IOC context. CTIP does not execute these actions.</p>
            {recommendations.length ? (
              <ul className="mitigation-recommendations">
                {recommendations.map((item, index) => (
                  <li key={`${index}-${item.recommendation}`}>
                    <strong>{item.recommendation}</strong>
                    <span className={`severity ${item.priority}`}>{item.priority} priority</span>
                    <p>{item.reason}</p>
                  </li>
                ))}
              </ul>
            ) : <p>No recommendations are available for this IOC.</p>}
          </div>

          <div className="enrichment-section operational-evidence">
            <div className="panel-header">
              <div>
                <h3>Operational Evidence</h3>
                <p>Observed evidence for this IOC in CTIP</p>
              </div>
              <span className="research-label">OPERATIONAL CTIP</span>
            </div>
            <div className="enrichment-grid">
              <div><span>Source Count</span><strong>{ioc.source_count ?? 0}</strong></div>
              <div><span>Observation Count</span><strong>{observationCount}</strong></div>
              <div><span>Observed Sources</span><strong>{correlation?.sources?.join(', ') || 'None'}</strong></div>
              <div><span>Threat Context</span><strong>{correlation?.threat_types?.join(', ') || record.threat_type || 'Unknown'}</strong></div>
              <div><span>Tags</span><strong>{record.tags?.join(', ') || 'None'}</strong></div>
            </div>
            <div className="research-relevance">
              <strong>Research relevance</strong>
              <p>Source diversity and observation evidence are represented in Experiment B; threat context and tags are represented in Experiment C. These are research feature families only; no research feature vector or prediction is generated for this IOC.</p>
            </div>
            <div className="observation-history">
              <h4>Observation History</h4>
              {Array.isArray(ioc.observations) && ioc.observations.length > 0 ? (
                <ul>
                  {ioc.observations.map((observation, index) => (
                    <li key={observation.id || `${observation.source}-${observation.observed_at}-${index}`}>
                      <strong>{observation.source}</strong>
                      <time dateTime={observation.observed_at || undefined}>
                        {observation.observed_at && !Number.isNaN(Date.parse(observation.observed_at))
                          ? new Date(observation.observed_at).toLocaleString()
                          : 'Timestamp unavailable'}
                      </time>
                    </li>
                  ))}
                </ul>
              ) : <p>No observations were returned for this IOC.</p>}
            </div>
          </div>

          <div className="risk-result">
            <div>
              <span>Production Risk · Deterministic CTIP Risk Engine</span>

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
            <h3>Operational CTIP · Deterministic Risk Breakdown</h3>
            <p>Severity contributes 60%; confidence contributes 40%.</p>
            <div className="enrichment-grid">
              <div>
                <span>Severity Score</span>
                <strong>{riskExplanation?.severity_score ?? '—'}/100</strong>
              </div>
              <div>
                <span>Severity Contribution (60%)</span>
                <strong>{riskExplanation?.severity_contribution ?? '—'}</strong>
              </div>
              <div>
                <span>Confidence Contribution (40%)</span>
                <strong>{riskExplanation?.confidence_contribution ?? '—'}</strong>
              </div>
              <div>
                <span>Final Deterministic Score</span>
                <strong>{riskExplanation?.final_deterministic_score ?? '—'}/100</strong>
              </div>
            </div>
          </div>

          <div className="enrichment-section investigation-research-context">
            <div className="panel-header">
              <div>
                <h3>Research &amp; AI Context</h3>
                <p>Research status is separate from this IOC's operational assessment.</p>
              </div>
              <span className="research-label synthetic">RESEARCH / AI</span>
            </div>
            <div className="research-context-grid">
              <div><span>Research Dataset</span><strong>{research?.research_dataset || 'Unavailable'}</strong></div>
              <div><span>Real Dataset Records</span><strong>{research?.research_records == null ? 'Unavailable' : Number(research.research_records).toLocaleString()}</strong></div>
              <div><span>Research Feature Space</span><strong>{research?.feature_count ?? 'Unavailable'} features</strong></div>
              <div><span>Experiment Configurations</span><strong>{research?.experiment_configurations?.join(' / ') || 'Unavailable'}</strong></div>
              <div><span>Research Model Status</span><strong>Not enabled for production</strong></div>
              <div><span>Real Supervised Labels</span><strong>{research?.real_supervised_label_count === 0 ? 'Not currently available' : 'Unavailable'}</strong></div>
              <div><span>Research Benchmark</span><strong>{research?.synthetic_benchmark_available ? 'Controlled synthetic dataset' : 'Unavailable'}</strong></div>
              <div><span>Production Risk</span><strong>Deterministic CTIP risk engine</strong></div>
            </div>
            {research?.available === false && (
              <p className="research-context-unavailable" role="status">Research artifacts are unavailable. Operational CTIP investigation and deterministic scoring are unaffected.</p>
            )}
            <p className="research-context-disclaimer">Not a production prediction. Synthetic benchmark outputs and explanation examples do not assess this IOC or explain its deterministic score.</p>
            {onNavigateResearch && (
              <button className="research-link-button" type="button" onClick={onNavigateResearch}>
                View research examples and synthetic benchmark status
              </button>
            )}
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
