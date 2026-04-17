import React from 'react'
import Footer from '@/components/layout/Footer'
import HeroBanner from '@/components/sections/HeroBanner'
import StatsSection  from '@/components/sections/StatisticsCards'
import FeaturesShowcase from '@/components/sections/FeaturesShowcase'
import PlatformTabs from '@/components/sections/PlatformTabs'
import HowItWorks from '@/components/sections/HowItWorks'
import FinalCta from '@/components/sections/FinalCta'

const Home: React.FC = () => {
  return (
    <div className="min-h-screen bg-background text-foreground">
      <Header />
      <main>
        <div id="page-home">
          <section id="home">
            <HeroBanner />
          </section>
          <section id="stats">
            <StatsSection />
          </section>
          <section id="features">
            <FeaturesShowcase />
            <PlatformTabs />
          </section>
          <section id="how-it-works">
            <HowItWorks />
          </section>
        </div>
      </main>
      
      <Footer />
    </div>
  )
}

export default Home
