'use client'

import React, { useState } from 'react'
import { Swiper, SwiperSlide } from 'swiper/react'
import { Navigation, Pagination, Autoplay } from 'swiper/modules'
import { motion } from 'framer-motion'
import { Mail, GraduationCap, ArrowRight } from 'lucide-react'
import Button from '../ui/Button'
import 'swiper/css'
import 'swiper/css/navigation'
import 'swiper/css/pagination'

const StatisticsCards: React.FC = () => {
  const [swiper, setSwiper] = useState<any>(null)

  const statsData = [
    {
      percentage: '4',
      description: 'verdict states: SAFE, SUSPICIOUS, MALICIOUS, DANGEROUS DATASET',
      icon: Mail,
      color: 'text-blue-600',
      bgColor: 'bg-blue-600',
      product: {
        name: 'Verdict Engine',
        description: 'Rule-based scoring combines keyword matches, categories, and context to classify repository risk',
        href: '/platform'
      }
    },
    {
      percentage: '6',
      description: 'source types scanned in the malware pipeline (.js, .ts, .py, .sh, .json, .env)',
      icon: GraduationCap,
      color: 'text-blue-600',
      bgColor: 'bg-blue-600',
      product: {
        name: 'Source Scanner',
        description: 'GitHub zipball extraction and filtered source inspection for suspicious indicators',
        href: '/platform'
      }
    },
    {
      percentage: '900s',
      description: 'default malware scan cache TTL to reduce repeated scans and latency',
      icon: GraduationCap,
      color: 'text-blue-600',
      bgColor: 'bg-blue-600',
      product: {
        name: 'Caching Layer',
        description: 'Redis-backed caching for analyze, AI scan, and malware scan responses',
        href: '/platform'
      }
    }
  ]

  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: {
        duration: 0.6,
        staggerChildren: 0.2
      }
    }
  }

  const slideVariants = {
    hidden: { y: 50, opacity: 0 },
    visible: {
      y: 0,
      opacity: 1,
      transition: {
        duration: 0.6
      }
    }
  }

  return (
    <section className="py-16 bg-gradient-to-r from-blue-600 to-blue-800 text-white">
      <div className="container mx-auto px-4">
        <motion.div
          className="max-w-6xl mx-auto"
          variants={containerVariants}
          initial="hidden"
          whileInView="visible"
          viewport={{ once: true }}
        >
          <Swiper
            modules={[Navigation, Pagination, Autoplay]}
            spaceBetween={30}
            slidesPerView={1}
            navigation={{
              nextEl: '.swiper-button-next',
              prevEl: '.swiper-button-prev',
            }}
            pagination={{
              clickable: true,
              el: '.swiper-pagination',
            }}
            autoplay={{
              delay: 5000,
              disableOnInteraction: false,
            }}
            loop={true}
            onSwiper={setSwiper}
            className="statistics-swiper"
          >
            {statsData.map((stat, index) => (
              <SwiperSlide key={index}>
                <motion.div
                  variants={slideVariants}
                  className="bg-white/10 backdrop-blur-lg rounded-2xl p-8 border border-white/20"
                >
                  <div className="grid md:grid-cols-2 gap-8 items-center">
                    {/* Left side - Percentage */}
                    <div className="text-center md:text-left">
                      <motion.div
                        className="text-6xl md:text-7xl font-bold mb-4"
                        initial={{ scale: 0 }}
                        whileInView={{ scale: 1 }}
                        transition={{ duration: 0.5, delay: 0.2 }}
                      >
                        {stat.percentage}
                      </motion.div>
                      <p className="text-lg text-blue-100 mb-6">
                        {stat.description}
                      </p>
                      
                      {/* Learn More Button */}
                      <div className="hidden md:block">
                        <Button
                          variant="secondary"
                          size="small"
                          className="text-white border-white hover:bg-white hover:text-blue-600"
                        >
                          Learn more
                        </Button>
                      </div>
                    </div>

                    {/* Right side - Product Info */}
                    <div className="bg-white/5 rounded-xl p-6 border border-white/10">
                      <div className="flex items-center mb-4">
                        <div className="bg-white/20 rounded-lg p-3 mr-4">
                          <stat.icon className="w-8 h-8 text-white" />
                        </div>
                        <h3 className="text-xl font-semibold">
                          <a
                            href={stat.product.href}
                            className="hover:text-blue-200 transition-colors"
                          >
                            {stat.product.name}
                          </a>
                        </h3>
                      </div>
                      
                      <p className="text-blue-100 mb-4 text-sm">
                        {stat.product.description}
                      </p>
                      
                      <Button
                        variant="secondary"
                        size="small"
                        href={stat.product.href}
                        className="text-white border-white hover:bg-white hover:text-blue-600 w-full md:w-auto"
                      >
                        Learn more
                      </Button>
                    </div>
                  </div>
                </motion.div>
              </SwiperSlide>
            ))}
          </Swiper>

          {/* Custom Navigation */}
          <div className="flex justify-center items-center mt-8 space-x-4">
            <button
              className="swiper-button-prev bg-white/20 hover:bg-white/30 rounded-full p-3 transition-colors"
              onClick={() => swiper?.slidePrev()}
            >
              <ArrowRight className="w-5 h-5 rotate-180" />
            </button>
            
            <div className="swiper-pagination flex space-x-2"></div>
            
            <button
              className="swiper-button-next bg-white/20 hover:bg-white/30 rounded-full p-3 transition-colors"
              onClick={() => swiper?.slideNext()}
            >
              <ArrowRight className="w-5 h-5" />
            </button>
          </div>
        </motion.div>
      </div>

      <style jsx>{`
        .statistics-swiper .swiper-pagination-bullet {
          background: rgba(255, 255, 255, 0.5);
          opacity: 1;
          width: 8px;
          height: 8px;
          margin: 0 4px;
        }
        
        .statistics-swiper .swiper-pagination-bullet-active {
          background: white;
        }
      `}</style>
    </section>
  )
}

export default StatisticsCards
