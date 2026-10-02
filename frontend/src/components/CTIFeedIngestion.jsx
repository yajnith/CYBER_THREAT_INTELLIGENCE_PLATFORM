import { useState } from 'react'

const AVAILABLE_FEEDS = [
  {
    id: 'sample_cti_feed',
    label: 'Sample CTI feed',
  },
  {
    id: 'sample_cti_csv',
    label: 'Sample CTI CSV feed',
  },
]

function CTIFeedIngestion({ onIngested }) {
  const [feedId, setFeedId] = useState(AVAILABLE_FEEDS[0].id)
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const ingestFeed = async (event) => {
    event.preventDefault()
    setLoading(true)
    setError('')
    setResult(null)

    try {
      const response = await fetch(
        `http://127.0.0.1:8000/api/v1/ingestion/feeds/${encodeURIComponent(feedId)}`,
        { method: 'POST' }
      )
      const data = await response.json().catch(() => ({}))

      if (!response.ok) {
        throw new Error(data.detail || 'Feed ingestion failed.')
      }

      if (!data || typeof data.feed_id !== 'string' || !Number.isFinite(data.records_processed)) {
        throw new Error('The CTIP API returned an incomplete ingestion summary.')
      }
      setResult(data)
      onIngested?.()
    } catch (err) {
      setError(
        err instanceof TypeError
          ? 'Could not reach the CTIP API. Check that the backend is running and try again.'
          : err.message
      )
    } finally {
      setLoading(false)
    }
  }

  return (
    <section className="investigation">
      <div className="investigation-header">
        <p className="eyebrow">ANALYST WORKSPACE</p>
        <h2>CTI Feed Ingestion</h2>
        <p>Ingest a project-local JSON or CSV feed through the CTIP processing pipeline.</p>
      </div>

      <div className="investigation-card feed-ingestion-card">
        <form onSubmit={ingestFeed}>
          <label className="feed-select-label" htmlFor="feed-id">
            Available feed
          </label>
          <select
            id="feed-id"
            value={feedId}
            onChange={(event) => setFeedId(event.target.value)}
            disabled={loading}
          >
            {AVAILABLE_FEEDS.map((feed) => (
              <option key={feed.id} value={feed.id}>
                {feed.label} ({feed.id})
              </option>
            ))}
          </select>
          <p className="feed-help-text">
            Feed files are maintained in the backend project&apos;s feeds directory.
          </p>
          <button
            type="submit"
            className="investigate-button"
            disabled={loading || !feedId}
          >
            {loading ? 'Ingesting feed…' : 'Ingest Feed'}
          </button>
        </form>

        {loading && (
          <div className="empty-state" role="status">
            Processing feed records and creating observations…
          </div>
        )}

        {error && (
          <div className="error-banner feed-message" role="alert">
            <strong>Feed ingestion failed</strong>
            <p>{error}</p>
          </div>
        )}

        {result && (
          <section className="feed-result" aria-live="polite">
            <div className="feed-success-banner" role="status">
              Feed ingestion completed successfully.
            </div>
            <div className="panel-header">
              <div>
                <h2>Ingestion Summary</h2>
                <p>Results returned by the CTIP API</p>
              </div>
              <span className="type-pill">{result.feed_id}</span>
            </div>
            <div className="feed-count-grid">
              <div><span>Feed ID</span><strong>{result.feed_id}</strong></div>
              <div><span>Records Processed</span><strong>{result.records_processed}</strong></div>
              <div><span>New IOCs</span><strong>{result.new_iocs}</strong></div>
              <div><span>Existing IOCs</span><strong>{result.existing_iocs}</strong></div>
              <div><span>Observations Created</span><strong>{result.observations_created}</strong></div>
            </div>
            {result.errors?.length > 0 && (
              <div className="feed-errors" role="alert">
                <h3>Record errors</h3>
                <ul>
                  {result.errors.map((item, index) => (
                    <li key={`${index}-${String(item)}`}>
                      {typeof item === 'string' ? item : JSON.stringify(item)}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </section>
        )}
      </div>
    </section>
  )
}

export default CTIFeedIngestion
