import React from 'react'
import Footer from '@/components/layout/Footer'
import HeroBanner from '@/components/sections/HeroBanner'
import StatsSection  from '@/components/sections/StatisticsCards'
import Technologies from '@/components/sections/Technologies'
import PlatformTabs from '@/components/sections/PlatformTabs'
import HowItWorks from '@/components/sections/HowItWorks'
import FinalCta from '@/components/sections/FinalCta'

const Home: React.FC = () => {
  return (
    <div className="min-h-screen bg-white">
      <main>
        <div id="page-home">
          <HeroBanner />
          <StatsSection />
          <Technologies />
          <PlatformTabs />
          <HowItWorks />
          <FinalCta />
        </div>
      </main>
      
      <Footer />
    </div>
  )
}

export default Home
