import React from 'react'
import AnalysisDashboardPage from '@/components/sections/analysis/AnalysisDashboardPage'

const AiAnalysisPage: React.FC = () => {
  return (
    <AnalysisDashboardPage
      config={{
        sectionLabel: 'AI Analysis',
        title: 'Repository AI Analysis Dashboard',
        subtitle:
          'Inspect model-generated repository insights with compliance checks, language distribution, and readiness scoring.',
        buttonLabel: 'Run AI Analysis',
        loadingLabel: 'Generating AI insights and repository quality signals...',
        scoreCardTitle: 'AI Readiness Score',
        scoreValue: '76 / 100',
        scoreCaption: 'Repository is suitable for AI-assisted review, with moderate compliance and quality gaps.',
        statusCard: {
          title: 'Compliance Card',
          value: 'PARTIALLY COMPLIANT',
          description: 'License is present and valid. README is available but missing architecture and contribution sections.',
          toneClassName: 'text-blue-600'
        },
        repoInfo: {
          name: 'leslief/gitguard-ai-eval',
          description: 'Repository profile used for AI readiness, quality trend, and policy checks.',
          metrics: [
            { label: 'License', value: 'MIT' },
            { label: 'README', value: 'Present' },
            { label: 'CI Status', value: 'Passing' },
            { label: 'Last Release', value: '14 days ago' }
          ]
        },
        distributionTitle: 'Language Distribution',
        distributionMetrics: [
          { label: 'TypeScript', value: 56 },
          { label: 'JavaScript', value: 22 },
          { label: 'Python', value: 14 },
          { label: 'Other', value: 8 }
        ],
        metricsTitle: 'Readiness / Quality Metrics',
        progressMetrics: [
          { label: 'Prompt-Friendly Documentation', value: '68%', progress: 68 },
          { label: 'Codebase Consistency', value: '81%', progress: 81 },
          { label: 'Test Signal Reliability', value: '74%', progress: 74 },
          { label: 'Dependency Hygiene', value: '79%', progress: 79 }
        ],
        summaryTitle: 'AI Summary',
        summaryText:
          'The repository is generally structured for AI-supported analysis with strong code organization and stable pipelines. Improvements in documentation depth and dependency review cadence would increase confidence and automation quality.',
        rawOutputTitle: 'Raw AI Output',
        rawOutput: {
          analyzer: 'ai-analysis-v2',
          model: 'gitguard-reasoner-16b',
          readinessScore: 76,
          compliance: {
            license: 'VALID_MIT',
            readme: 'PRESENT_PARTIAL',
            contributionGuidelines: 'MISSING'
          },
          recommendations: [
            'Expand README architecture section with module boundaries.',
            'Add examples for expected input and output formats.',
            'Define semantic versioning and release checklist.'
          ],
          generatedAt: '2026-04-17T10:31:00.000Z'
        }
      }}
    />
  )
}

export default AiAnalysisPage
