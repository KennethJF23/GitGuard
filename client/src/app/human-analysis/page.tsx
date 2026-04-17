import React from 'react'
import AnalysisDashboardPage from '@/components/sections/analysis/AnalysisDashboardPage'

const HumanAnalysisPage: React.FC = () => {
  return (
    <AnalysisDashboardPage
      config={{
        sectionLabel: 'Human Analysis',
        title: 'Repository Human Analysis Dashboard',
        subtitle:
          'Review repository trust signals with clear score logic, repository metadata, and practical next actions for maintainers.',
        buttonLabel: 'Run Human Analysis',
        loadingLabel: 'Analyzing repository metadata and heuristics...',
        scoreCardTitle: 'Human Trust Score',
        scoreValue: '82 / 100',
        scoreCaption: 'Strong repository hygiene with room to improve maintenance and testing consistency.',
        repoInfo: {
          name: 'leslief/gitguard-demo-repo',
          description: 'A sample repository scanned through GitGuard human heuristics and activity checks.',
          metrics: [
            { label: 'Stars', value: '1.2k' },
            { label: 'Forks', value: '148' },
            { label: 'Open Issues', value: '12' },
            { label: 'Commits (30d)', value: '36' }
          ]
        },
        distributionTitle: 'Score Breakdown',
        distributionMetrics: [
          { label: 'Code Maintainability', value: 84 },
          { label: 'Documentation Quality', value: 78 },
          { label: 'Security Posture', value: 86 },
          { label: 'Community Signals', value: 73 }
        ],
        metricsTitle: 'Activity Metrics',
        progressMetrics: [
          { label: 'Issue Resolution Rate', value: '71%', progress: 71 },
          { label: 'Pull Request Throughput', value: '64%', progress: 64 },
          { label: 'Release Cadence Stability', value: '83%', progress: 83 },
          { label: 'Contributor Responsiveness', value: '76%', progress: 76 }
        ],
        summaryTitle: 'Summary',
        summaryText:
          'The repository shows healthy contributor activity and consistent release behavior. Most low-risk findings are tied to uneven documentation detail and a small backlog of unresolved issues.',
        roadmapTitle: 'Roadmap',
        roadmapItems: [
          'Add contributing and security policy docs for onboarding clarity.',
          'Tag issues with risk and priority labels for faster triage.',
          'Increase automated test coverage for core execution paths.',
          'Formalize release notes with security-impact sections.'
        ],
        rawOutputTitle: 'Raw Analysis Output',
        rawOutput: {
          analyzer: 'human-analysis-v1',
          score: 82,
          confidence: 0.89,
          verdict: 'LOW_TO_MEDIUM_RISK',
          highlights: {
            strongSignals: ['active_maintainers', 'regular_commits', 'clear_dependency_locking'],
            weakSignals: ['limited_security_docs', 'issue_backlog_spike']
          },
          generatedAt: '2026-04-17T10:24:00.000Z'
        }
      }}
    />
  )
}

export default HumanAnalysisPage
