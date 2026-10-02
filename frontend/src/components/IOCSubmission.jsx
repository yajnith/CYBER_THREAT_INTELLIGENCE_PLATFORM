import { useState } from 'react'

function IOCSubmission({ onSubmitted }) {
  const [form, setForm] = useState({
    indicator_type: 'domain',
    value: '',
    source: 'manual',
    threat_type: '',
    confidence: 50,
    severity: 'medium',
    tags: '',
  })

  const [loading, setLoading] = useState(false)
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  const [result, setResult] = useState(null)

  const handleChange = (event) => {
    const { name, value } = event.target

    setForm((previous) => ({
      ...previous,
      [name]: value,
    }))
  }

  const handleSubmit = async (event) => {
    event.preventDefault()

    setLoading(true)
    setMessage('')
    setError('')
    setResult(null)

    const payload = {
      indicator_type: form.indicator_type,
      value: form.value.trim(),
      source: form.source.trim(),
      threat_type: form.threat_type.trim() || null,
      confidence: Number(form.confidence),
      severity: form.severity,
      tags: form.tags
        .split(',')
        .map((tag) => tag.trim())
        .filter(Boolean),
    }

    try {
      const response = await fetch(
        'http://127.0.0.1:8000/api/v1/iocs',
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(payload),
        }
      )

      const data = await response.json().catch(() => ({}))

      if (!response.ok) {
        const detail = Array.isArray(data.detail)
          ? data.detail.map((item) => item.msg || JSON.stringify(item)).join('; ')
          : data.detail
        throw new Error(typeof detail === 'string' ? detail : 'Failed to submit IOC')
      }

      if (!data?.ioc || typeof data.ioc.normalized_value !== 'string') {
        throw new Error('The CTIP API returned an incomplete IOC submission response.')
      }

      setResult(data)
      setMessage(data.is_new
        ? 'New IOC created and processed successfully.'
        : 'Existing IOC matched; a new source observation was recorded.')
      onSubmitted?.()

      setForm({
        indicator_type: 'domain',
        value: '',
        source: 'manual',
        threat_type: '',
        confidence: 50,
        severity: 'medium',
        tags: '',
      })
    } catch (err) {
      setError(err instanceof TypeError
        ? 'Could not reach the CTIP API. Check that the backend is running and try again.'
        : err.message)
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

        <h2>Submit IOC</h2>

        <p>
          Add a new indicator to the threat intelligence platform.
        </p>
      </div>

      <div className="investigation-card">

        <form onSubmit={handleSubmit}>

          <div className="investigation-grid">

            <div>
              <span>Indicator Type</span>

              <select
                name="indicator_type"
                value={form.indicator_type}
                onChange={handleChange}
              >
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
              <span>IOC Value</span>

              <input
                type="text"
                name="value"
                value={form.value}
                onChange={handleChange}
                placeholder="Enter IOC..."
                required
              />
            </div>

            <div>
              <span>Source</span>

              <input
                type="text"
                name="source"
                value={form.source}
                onChange={handleChange}
                placeholder="e.g. manual, OSINT"
                required
              />
            </div>

            <div>
              <span>Threat Type</span>

              <input
                type="text"
                name="threat_type"
                value={form.threat_type}
                onChange={handleChange}
                placeholder="e.g. phishing"
              />
            </div>

            <div>
              <span>Confidence</span>

              <input
                type="number"
                name="confidence"
                min="0"
                max="100"
                value={form.confidence}
                onChange={handleChange}
                required
              />
            </div>

            <div>
              <span>Severity</span>

              <select
                name="severity"
                value={form.severity}
                onChange={handleChange}
              >
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
              </select>
            </div>

            <div>
              <span>Tags</span>

              <input
                type="text"
                name="tags"
                value={form.tags}
                onChange={handleChange}
                placeholder="e.g. malware, phishing"
              />
            </div>

          </div>

          <button
            type="submit"
            className="investigate-button"
            disabled={loading}
          >
            {loading ? 'Submitting...' : 'Submit IOC'}
          </button>

        </form>

        {message && (
          <div className="risk-result">
            <h3>{message}</h3>

            {result && (
              <>
                <p>
                  <strong>Deterministic CTIP Risk:</strong>{' '}
                  {result.risk_score}
                </p>

                <p>
                  <strong>Risk Level:</strong>{' '}
                  {result.risk_level}
                </p>

                <p>
                  <strong>Normalized Value:</strong>{' '}
                  {result.ioc.normalized_value}
                </p>
              </>
            )}
          </div>
        )}

        {error && (
          <div className="risk-result">
            <h3>Submission failed</h3>

            <p>{error}</p>
          </div>
        )}

      </div>
    </section>
  )
}

export default IOCSubmission
