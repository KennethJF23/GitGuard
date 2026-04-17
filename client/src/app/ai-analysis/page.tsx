import React from 'react'
import AnalysisDashboardPage from '@/components/sections/analysis/AnalysisDashboardPage'

const AiAnalysisPage: React.FC = () => {
  return (
    <AnalysisDashboardPage
      config={{
        mode: 'ai',
        sectionLabel: 'AI Analysis',
        title: 'Repository AI Analysis Dashboard',
        subtitle:
          'Run backend AI scan and inspect metadata-driven repository insights in a consistent dashboard format.',
        buttonLabel: 'Run AI Analysis',
        loadingLabel: 'Generating backend AI scan and repository quality signals...',
      }}
    />
  )
}

export default AiAnalysisPage
