import React from 'react'
import AnalysisDashboardPage from '@/components/sections/analysis/AnalysisDashboardPage'

const HumanAnalysisPage: React.FC = () => {
  return (
    <AnalysisDashboardPage
      config={{
        mode: 'human',
        sectionLabel: 'Human Analysis',
        title: 'Repository Human Analysis Dashboard',
        subtitle: 'Review backend repository trust signals with transparent scoring and actionable insights.',
        buttonLabel: 'Run Human Analysis',
        loadingLabel: 'Analyzing repository metadata and heuristics from backend...',
      }}
    />
  )
}

export default HumanAnalysisPage
