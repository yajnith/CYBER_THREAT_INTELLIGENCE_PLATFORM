import { useEffect, useMemo, useState } from 'react'
import BarChart from './BarChart'

const API_BASE = 'http://127.0.0.1:8000/api/v1/research'
const METRICS = [
  ['accuracy', 'Accuracy'],
  ['precision', 'Precision'],
  ['recall', 'Recall'],
  ['f1', 'F1'],
  ['roc_auc', 'AUC'],
]

function ResearchOverview() {
  const [overview, setOverview] = useState(null)
  const [summary, setSummary] = useState(null)
  const [explanationArtifact, setExplanationArtifact] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [summaryError, setSummaryError] = useState('')
  const [explanationError, setExplanationError] = useState('')
  const [explorerSearch, setExplorerSearch] = useState('')
  const [explorerStatus, setExplorerStatus] = useState('')
  const [submittedSearch, setSubmittedSearch] = useState('')
  const [explorerPage, setExplorerPage] = useState(1)
  const [explorerData, setExplorerData] = useState(null)
  const [explorerLoading, setExplorerLoading] = useState(false)
  const [explorerError, setExplorerError] = useState('')
  const [explanationExperiment, setExplanationExperiment] = useState('C')
  const [explanationModel, setExplanationModel] = useState('LogisticRegression')
  const [localExampleIndex, setLocalExampleIndex] = useState(0)

  useEffect(() => {
    fetchJson(`${API_BASE}/overview`)
      .then((data) => setOverview(data))
      .catch((requestError) => setError(requestError.message))
      .finally(() => setLoading(false))

    fetchJson(`${API_BASE}/urlhaus/summary`)
      .then((data) => setSummary(data))
      .catch((requestError) => setSummaryError(requestError.message))

    fetchJson(`${API_BASE}/explainability`)
      .then((data) => setExplanationArtifact(data))
      .catch((requestError) => setExplanationError(requestError.message))
  }, [])

  useEffect(() => {
    const params = new URLSearchParams({ page: String(explorerPage), page_size: '25' })
    if (submittedSearch) params.set('search', submittedSearch)
    if (explorerStatus) params.set('status', explorerStatus)
    setExplorerLoading(true)
    setExplorerError('')
    fetchJson(`${API_BASE}/urlhaus/records?${params.toString()}`)
      .then((data) => setExplorerData(data))
      .catch((requestError) => setExplorerError(requestError.message))
      .finally(() => setExplorerLoading(false))
  }, [submittedSearch, explorerStatus, explorerPage])

  const explanationExperiments = Object.keys(explanationArtifact?.experiments || {})
  const availableModels = Object.keys(explanationArtifact?.experiments?.[explanationExperiment]?.models || {})
  const selectedExplanation = explanationArtifact?.experiments?.[explanationExperiment]?.models?.[explanationModel]
  const localExamples = selectedExplanation?.local_explanations || []
  const localExample = localExamples[localExampleIndex]

  useEffect(() => {
    if (explanationExperiments.length && !explanationExperiments.includes(explanationExperiment)) {
      setExplanationExperiment(explanationExperiments.includes('C') ? 'C' : explanationExperiments[0])
    }
  }, [explanationExperiments.join('|'), explanationExperiment])

  useEffect(() => {
    if (availableModels.length && !availableModels.includes(explanationModel)) {
      setExplanationModel(availableModels[0])
    }
  }, [availableModels.join('|'), explanationModel])

  useEffect(() => setLocalExampleIndex(0), [explanationExperiment, explanationModel])

  if (loading) return <div className="empty-state">Loading research overview...</div>
  if (error) {
    return <div className="research-page"><ResearchHeader /><div className="error-banner">Unable to load the research overview: {error}</div></div>
  }

  const benchmark = overview.benchmark
  const experiments = overview.experiments || []
  const performanceByMetric = Object.fromEntries(METRICS.map(([key, label]) => [
    key,
    experiments.flatMap((experiment) => Object.entries(experiment.models || {}).flatMap(([model, result]) => {
      const value = result.metrics?.[key]
      if (typeof value !== 'number' || !Number.isFinite(value)) return []
      return [{
        label: `${experiment.id} · ${displayModel(model)}`,
        value,
        tooltip: `${experiment.id} · ${displayModel(model)} · ${label}: ${value} (${(value * 100).toFixed(4)}%)`,
      }]
    })),
  ]))

  return (
    <div className="research-page">
      <ResearchHeader />

      <section className="panel research-datasets">
        <div className="panel-header">
          <div><h2>Dataset Overview</h2><p>Complete real URLhaus CTI dataset, profiled from normalized records</p></div>
          <span className="research-label real">REAL CTI DATA</span>
        </div>
        {summaryError ? <div className="research-unavailable">Unable to load URLhaus analytics: {summaryError}</div> : !summary ? (
          <div className="empty-state">Loading URLhaus dataset analytics...</div>
        ) : (
          <>
            <div className="research-dataset-kpis">
              <ResearchStat label="URLhaus Records" value={formatValue(summary.record_count)} />
              <ResearchStat label="Unique URLs" value={formatValue(summary.unique_url_count)} />
              <ResearchStat label="Online" value={formatValue(summary.url_status_distribution?.online)} />
              <ResearchStat label="Offline" value={formatValue(summary.url_status_distribution?.offline)} />
              <ResearchStat label="Unique Reporters" value={formatValue(summary.unique_reporter_count)} />
              <ResearchStat label="Engineered Features" value={formatValue(summary.feature_count)} />
            </div>
            <p className="research-footnote">IOC type: {summary.ioc_type?.toUpperCase() || 'URL'} · Threats: {Object.entries(summary.threat_distribution || {}).map(([threat, count]) => `${threat} (${formatValue(count)})`).join(' · ')} · Duplicate URLs: {formatValue(summary.duplicate_url_count)}</p>
            <p className="research-real-label-note"><strong>REAL LABEL STATUS</strong> Supervised real-world labels: {formatValue(summary.supervised_label_count)}. The URLhaus dataset is real CTI data, but validated supervised labels are not available. Therefore real-world supervised model performance is not claimed.</p>
            <div className="research-dataset-charts">
              <DatasetChart title="URL Status Distribution" items={distributionItems(summary.url_status_distribution)} color="green" />
              <DatasetChart title="Threat Distribution" items={distributionItems(summary.threat_distribution)} color="amber" />
              <DatasetChart title="Top Tags" items={summary.top_tags} color="purple" />
              <DatasetChart title="Top Reporters" items={summary.top_reporters} color="blue" />
              <div className="research-subchart">
                <h3>Temporal Distribution</h3>
                <p>URLhaus <code>date_added</code> counts by month</p>
                <BarChart items={summary.temporal_distribution_by_month} label="URLhaus date_added records by month" color="green" axisLabel="records" />
              </div>
            </div>
            <p className="research-footnote">Date range: {summary.date_range?.first_date_added || 'No date_added values'} – {summary.date_range?.last_date_added || 'No date_added values'} · date_added present: {formatValue(summary.date_added_coverage?.present)} · last_online present: {formatValue(summary.last_online_coverage?.present)}</p>
          </>
        )}
      </section>

      <section className="panel research-explorer">
        <div className="panel-header">
          <div><h2>URLhaus Dataset Explorer</h2><p>Search and inspect normalized source records using server-side pagination.</p></div>
          <span className="record-count">{formatValue(explorerData?.dataset_record_count ?? summary?.record_count)} records</span>
        </div>
        <form className="dataset-explorer-controls" onSubmit={(event) => { event.preventDefault(); setExplorerPage(1); setSubmittedSearch(explorerSearch.trim()) }}>
          <label className="explorer-search-label">Search URL, reporter, threat, tags, ID, or date
            <input value={explorerSearch} onChange={(event) => setExplorerSearch(event.target.value)} placeholder="Search normalized URLhaus records" />
          </label>
          <label className="research-select-label">Status
            <select value={explorerStatus} onChange={(event) => { setExplorerStatus(event.target.value); setExplorerPage(1) }}>
              <option value="">All statuses</option><option value="online">Online</option><option value="offline">Offline</option>
            </select>
          </label>
          <button type="submit" className="investigate-button">Search records</button>
        </form>
        {explorerError && <div className="error-banner">Unable to load URLhaus records: {explorerError}</div>}
        <div className="table-wrapper research-explorer-table">
          <table>
            <thead><tr><th>IOC URL</th><th>Status</th><th>Threat</th><th>Reporter</th><th>Date Added</th><th>Last Online</th><th>Tags</th></tr></thead>
            <tbody>
              {(explorerData?.records || []).map((record) => (
                <tr key={record.urlhaus_id}>
                  <td className="indicator"><a href={record.urlhaus_link} target="_blank" rel="noreferrer">{record.url}</a></td>
                  <td>{record.url_status || '—'}</td><td>{record.threat || '—'}</td><td>{record.reporter || '—'}</td>
                  <td>{record.date_added || '—'}</td><td>{record.last_online || '—'}</td><td>{(record.tags || []).join(', ') || '—'}</td>
                </tr>
              ))}
              {!explorerLoading && explorerData?.records?.length === 0 && <tr><td colSpan="7">No matching URLhaus records.</td></tr>}
            </tbody>
          </table>
        </div>
        <div className="dataset-explorer-pagination">
          <span>{explorerLoading ? 'Loading records…' : `Page ${formatValue(explorerData?.page)} of ${formatValue(explorerData?.total_pages)} · ${formatValue(explorerData?.total_records)} matching records`}</span>
          <div><button type="button" disabled={explorerLoading || explorerPage <= 1} onClick={() => setExplorerPage((page) => Math.max(1, page - 1))}>Previous</button><button type="button" disabled={explorerLoading || explorerPage >= (explorerData?.total_pages || 1)} onClick={() => setExplorerPage((page) => page + 1)}>Next</button></div>
        </div>
      </section>

      <section className="panel">
        <div className="panel-header"><div><h2>Feature Engineering</h2><p>Feature configurations used by the A/B/C research experiments</p></div></div>
        <div className="research-experiment-grid">
          {experiments.map((experiment) => (
            <article className="research-experiment" key={experiment.id}>
              <span className="research-experiment-id">Feature Set {experiment.id}</span>
              <h3>{experiment.name}</h3>
              <strong>{formatValue(experiment.feature_count)} <small>features</small></strong>
              <p>{formatValue(experiment.row_count)} feature rows</p>
            </article>
          ))}
        </div>
        <BarChart items={experiments.map((experiment) => ({ label: `Feature Set ${experiment.id}`, value: experiment.feature_count, tooltip: `${experiment.id}: ${experiment.feature_count} features` }))} label="Feature count progression from A to C" color="blue" axisLabel="features" />
      </section>

      <section className="panel research-synthetic">
        <div className="panel-header"><div><h2>ML Benchmark · Model Comparison</h2><p>Existing Logistic Regression and Gaussian Naive Bayes results across feature sets A/B/C.</p></div><span className="research-label synthetic">CONTROLLED SYNTHETIC BENCHMARK</span></div>
        {benchmark.available ? (
          <>
            <div className="research-dataset-kpis benchmark-kpis">
              <ResearchStat label="Samples" value={formatValue(benchmark.samples)} />
              <ResearchStat label="Class Balance" value={`${formatValue(benchmark.positive)} / ${formatValue(benchmark.negative)}`} />
              <ResearchStat label="Train / Test" value={`${formatValue(benchmark.train_size ?? 450)} / ${formatValue(benchmark.test_size ?? 150)}`} />
              <ResearchStat label="Benchmark Seed" value={formatValue(benchmark.seed)} />
              <ResearchStat label="Split Seed" value={formatValue(benchmark.split_seed)} />
            </div>
            <p className="research-metric-disclaimer"><strong>Controlled synthetic benchmark — not trained/evaluated on validated real URLhaus labels. Not production CTIP risk performance.</strong></p>
            <div className="research-metric-chart-grid">
              {METRICS.map(([metric, label]) => (
                <DatasetChart key={metric} title={`${label} by Feature Configuration`} items={performanceByMetric[metric].map((item) => ({ ...item, value: item.value * 100, tooltip: item.tooltip }))} color={metric === 'roc_auc' ? 'purple' : 'blue'} axisLabel="percent" formatValue={(value) => `${value.toFixed(2)}%`} />
              ))}
            </div>
            <div className="table-wrapper research-table-wrap">
              <table>
                <caption>Controlled synthetic benchmark · all six model and feature-set results</caption>
                <thead><tr><th>Model</th><th>Feature Set</th><th>Accuracy</th><th>Precision</th><th>Recall</th><th>F1</th><th>AUC</th></tr></thead>
                <tbody>{experiments.flatMap((experiment) => Object.entries(experiment.models || {}).map(([model, result]) => (
                  <tr key={`${experiment.id}-${model}`}>
                    <td>{displayModel(model)}</td><td>Feature Set {experiment.id}</td>
                    {METRICS.map(([key]) => <td key={key} title={typeof result.metrics?.[key] === 'number' ? `Raw artifact value: ${result.metrics[key]}` : undefined}>{formatMetric(result.metrics?.[key])}</td>)}
                  </tr>
                )))}</tbody>
              </table>
            </div>
          </>
        ) : <div className="research-unavailable">The controlled benchmark artifact is unavailable; no metrics are inferred.</div>}
      </section>

      <section className="panel">
        <div className="panel-header"><div><h2>Explainability</h2><p>Artifact-backed model explanations from the controlled synthetic benchmark</p></div><span className="research-label synthetic">SYNTHETIC BENCHMARK ONLY</span></div>
        {explanationError ? <div className="research-unavailable">Unable to load the existing explanation artifact: {explanationError}</div> : !selectedExplanation ? (
          <div className="research-unavailable">The selected experiment/model explanation values are unavailable in the artifact.</div>
        ) : (
          <>
            <div className="research-select-group explanation-selectors">
              <SelectField label="Feature Set" value={explanationExperiment} onChange={setExplanationExperiment} options={explanationExperiments.map((value) => [value, `Feature Set ${value}`])} />
              <SelectField label="Model" value={explanationModel} onChange={setExplanationModel} options={availableModels.map((value) => [value, displayModel(value)])} />
              <SelectField label="Local example" value={String(localExampleIndex)} onChange={(value) => setLocalExampleIndex(Number(value))} options={localExamples.map((item, index) => [String(index), `${item.benchmark_row_id} · predicted ${item.predicted_class}`])} />
            </div>
            <p className="research-footnote">Attribution method: {selectedExplanation.attribution_method || 'Not specified in artifact.'} Contribution direction: {selectedExplanation.contribution_direction || 'Not specified in artifact.'}</p>
            <div className="research-explainability-grid">
              <div className="research-subchart"><h3>Global Mean Absolute Contribution</h3><BarChart items={(selectedExplanation.global_model_feature_contribution?.features_ranked_by_mean_absolute_contribution || []).slice(0, 12).map((item) => ({ label: item.feature, value: item.mean_absolute_contribution, tooltip: `${item.feature}: mean absolute=${item.mean_absolute_contribution}; signed mean=${item.mean_signed_contribution}` }))} label="Global mean absolute model feature contribution" color="purple" axisLabel="mean absolute contribution" /></div>
              <div className="research-subchart"><h3>Feature-Group Contribution</h3><BarChart items={Object.entries(selectedExplanation.feature_group_contribution?.groups || {}).map(([group, value]) => ({ label: group.replaceAll('_', ' '), value: value.mean_absolute_contribution_per_example, tooltip: `${group}: mean absolute contribution per example ${value.mean_absolute_contribution_per_example}; per-feature ${value.mean_absolute_contribution_per_feature_per_example}; signed mean ${value.mean_signed_contribution_per_example}` }))} label="Mean absolute model contribution by feature group" color="blue" axisLabel="mean absolute contribution per example" /></div>
            </div>
            {localExample && (
              <div className="research-local-example">
                <h3>Local Model Explanation · {localExample.benchmark_row_id}</h3>
                <div className="research-dataset-kpis local-explanation-kpis">
                  <ResearchStat label="Actual Class" value={localExample.actual_target} />
                  <ResearchStat label="Predicted Class" value={localExample.predicted_class} />
                  <ResearchStat label="Positive Class Probability" value={formatProbability(localExample.positive_class_probability)} />
                  <ResearchStat label="Contribution Sum" value={formatValue(localExample.sum_feature_contributions)} />
                </div>
                <div className="research-explainability-grid">
                  <div className="research-subchart"><h3>Positive Contributions</h3><BarChart items={(localExample.top_positive_contributing_features || []).map((item) => ({ label: item.feature, value: Math.abs(item.contribution), tooltip: `${item.feature} (${item.feature_group}): contribution +${item.contribution}; encoded value ${item.encoded_feature_value}` }))} label="Positive local feature contributions" color="green" axisLabel="contribution magnitude" /></div>
                  <div className="research-subchart"><h3>Negative Contributions</h3><BarChart items={(localExample.top_negative_contributing_features || []).map((item) => ({ label: item.feature, value: Math.abs(item.contribution), tooltip: `${item.feature} (${item.feature_group}): contribution ${item.contribution}; encoded value ${item.encoded_feature_value}` }))} label="Negative local feature contributions" color="amber" axisLabel="contribution magnitude" /></div>
                </div>
                <p className="research-footnote">Direction: positive contributions push toward the positive class; negative contributions push toward the negative class. Base log-odds: {formatValue(localExample.base_log_odds)} · reconstructed log-odds: {formatValue(localExample.reconstructed_log_odds)}.</p>
              </div>
            )}
            <p className="research-metric-disclaimer">These explanations describe controlled synthetic benchmark rows. They are not causal explanations, real URLhaus classifications, real IOC assessments, or the production deterministic risk score.</p>
          </>
        )}
      </section>

      <section className="panel research-implementation-status">
        <div className="panel-header"><div><h2>Research Status and Production Separation</h2><p>Research model artifacts do not control operational IOC risk.</p></div></div>
        <div className="research-capabilities">
          <ResearchCapability title="PRODUCTION RISK · Deterministic CTIP risk engine" status="Active" />
          <ResearchCapability title="PRODUCTION ML · Prediction service" status="Not enabled" />
          <ResearchCapability title="RESEARCH ML · Logistic Regression + Gaussian Naive Bayes" status={benchmark.available ? 'Benchmark artifact available' : 'Artifact unavailable'} />
          <ResearchCapability title="REAL SUPERVISED LABELS" status={`${formatValue(summary?.supervised_label_count)} available`} />
        </div>
        <p className="research-footnote">Production CTIP uses normalized IOC records, observations, deduplication, deterministic correlation and deterministic risk scoring. The research benchmark is separate.</p>
      </section>
    </div>
  )
}

function ResearchHeader() {
  return <header className="topbar"><div><p className="eyebrow">CTIP RESEARCH</p><h1>Research &amp; AI</h1><p className="subtitle">Real URLhaus analytics, feature engineering, controlled model comparison and artifact-backed explanations.</p></div><div className="research-label">RESEARCH DATA</div></header>
}

function DatasetChart({ title, items, color, formatValue }) {
  return <div className="research-subchart"><h3>{title}</h3><BarChart items={items || []} label={title} color={color} axisLabel="records" {...(formatValue ? { formatValue } : {})} /></div>
}

function ResearchStat({ label, value }) {
  return <div className="research-stat"><span>{label}</span><strong>{value ?? 'Not available in artifact'}</strong></div>
}

function ResearchCapability({ title, status }) {
  const active = status === 'Active' || status === 'Benchmark artifact available'
  return <div className="research-capability"><span className={active ? 'capability-dot available' : 'capability-dot'}></span><strong>{title}</strong><span>{status}</span></div>
}

function SelectField({ label, value, onChange, options }) {
  return <label className="research-select-label">{label}<select value={value} onChange={(event) => onChange(event.target.value)}>{options.map(([optionValue, text]) => <option key={optionValue} value={optionValue}>{text}</option>)}</select></label>
}

async function fetchJson(url) {
  const response = await fetch(url)
  if (!response.ok) {
    let detail = ''
    try { detail = (await response.json()).detail || '' } catch { /* use status text */ }
    throw new Error(detail || `Research API returned ${response.status}`)
  }
  return response.json()
}

function distributionItems(distribution) {
  if (!distribution || typeof distribution !== 'object') return []
  return Object.entries(distribution).map(([label, value]) => ({ label, value }))
}

function displayModel(model) {
  if (model === 'LogisticRegression') return 'Logistic Regression'
  if (model === 'GaussianNaiveBayes') return 'Gaussian Naive Bayes'
  return model
}

function formatValue(value) {
  if (typeof value === 'number' && Number.isFinite(value)) return value.toLocaleString()
  if (typeof value === 'string' && value.length > 0) return value
  return 'Not available in artifact'
}

function formatMetric(value) {
  return typeof value === 'number' ? `${(value * 100).toFixed(4)}%` : 'Not available in artifact'
}

function formatProbability(value) {
  return typeof value === 'number' ? `${(value * 100).toFixed(4)}%` : 'Not available in artifact'
}

export default ResearchOverview
