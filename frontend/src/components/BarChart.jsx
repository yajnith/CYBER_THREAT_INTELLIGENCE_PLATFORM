function BarChart({
  items = [],
  maxValue,
  formatValue = (value) => value.toLocaleString(),
  label = 'Data chart',
  color = 'blue',
  axisLabel = 'value',
}) {
  const usableItems = items.filter(
    (item) => typeof item.value === 'number' && Number.isFinite(item.value) && item.value >= 0,
  )

  if (!usableItems.length) {
    return <div className="chart-unavailable">Chart data unavailable.</div>
  }

  const scale = maxValue ?? Math.max(...usableItems.map((item) => item.value), 0)

  return (
    <div className="bar-chart" role="img" aria-label={label}>
      {usableItems.map((item, index) => {
        const width = scale > 0 ? Math.min((item.value / scale) * 100, 100) : 0
        const exactValue = formatValue(item.value)
        return (
          <div className="bar-chart-row" key={`${item.label}-${index}`} title={item.tooltip || `${item.label}: ${exactValue}`}>
            <span className="bar-chart-label">{item.label}</span>
            <span className="bar-chart-track">
              <span className={`bar-chart-fill ${color}`} style={{ width: `${width}%` }} />
            </span>
            <strong className="bar-chart-value">{exactValue}</strong>
          </div>
        )
      })}
      <div className="bar-chart-axis" aria-hidden="true">
        <span>0 {axisLabel}</span>
        <span>{formatValue(scale)} {axisLabel}</span>
      </div>
    </div>
  )
}

export default BarChart
