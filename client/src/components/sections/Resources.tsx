'use client'

import React from 'react'
import { motion } from 'framer-motion'
import { Calendar, FileText, ArrowRight } from 'lucide-react'
import Button from '../ui/Button'
import Image from 'next/image'

const Resources: React.FC = () => {
  const featuredArticle = {
    image: '/images/pawel-czerwinski-8uZPynIu-rQ-unsplash-scaled.webp',
    category: 'Backend',
    categoryColor: '#b57a97',
    date: '17.04.2026',
    title: 'How GitGuard classifies SAFE, SUSPICIOUS, MALICIOUS, and DANGEROUS DATASET',
    href: '/resources/news/gitguard-verdict-engine'
  }

  const otherArticles = [
    {
      category: 'Auth',
      categoryColor: '#f38c6d',
      date: '17.04.2026',
      title: 'JWT register/login flow and Bearer token middleware in GitGuard',
      href: '/resources/news/gitguard-jwt-auth-flow'
    },
    {
      category: 'Performance',
      categoryColor: '#f38c6d',
      date: '17.04.2026',
      title: 'Redis cache strategy for analyze, AI scan, and malware scan responses',
      href: '/resources/news/gitguard-redis-caching'
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

  const cardVariants = {
    hidden: { y: 30, opacity: 0 },
    visible: {
      y: 0,
      opacity: 1,
      transition: {
        duration: 0.5
      }
    }
  }

  return (
    <section className="py-16 bg-white">
      <div className="container mx-auto px-4">
        {/* Section Title */}
        <motion.div
          className="text-center mb-16"
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          viewport={{ once: true }}
        >
          <div className="inline-flex items-center justify-center mb-8">
            <div className="h-px bg-gray-300 w-20"></div>
            <h2 className="px-6 text-2xl font-semibold uppercase tracking-wider text-gray-900">
              resources
            </h2>
            <div className="h-px bg-gray-300 w-20"></div>
          </div>
        </motion.div>

        <motion.div
          className="grid lg:grid-cols-2 gap-12 max-w-6xl mx-auto"
          variants={containerVariants}
          initial="hidden"
          whileInView="visible"
          viewport={{ once: true }}
        >
          {/* Featured Article */}
          <motion.div variants={cardVariants}>
            <div className="group cursor-pointer">
              {/* Article Image */}
              <div className="relative mb-6 overflow-hidden rounded-xl">
                <div
                  className="absolute inset-0 bg-cover bg-center bg-no-repeat transition-transform duration-500 group-hover:scale-110"
                  style={{ backgroundImage: `url(${featuredArticle.image})` }}
                  onError={(e) => {
                    const target = e.target as HTMLDivElement;
                    target.style.backgroundImage = 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)';
                  }}
                ></div>
                <div className="relative pt-[60%]"></div>
              </div>

              {/* Article Content */}
              <div className="space-y-4">
                {/* Category and Date */}
                <div className="flex items-center justify-between">
                  <span
                    className="text-sm font-medium px-3 py-1 rounded-full"
                    style={{ color: featuredArticle.categoryColor }}
                  >
                    {featuredArticle.category}
                  </span>
                  <div className="flex items-center text-gray-500 text-sm">
                    <Calendar className="w-4 h-4 mr-1" />
                    {featuredArticle.date}
                  </div>
                </div>

                {/* Title */}
                <h3 className="text-xl font-semibold text-gray-900 group-hover:text-blue-600 transition-colors">
                  <a href={featuredArticle.href}>
                    {featuredArticle.title}
                  </a>
                </h3>

                {/* Read More Button */}
                <div className="flex items-center justify-between">
                  <Button
                    variant="secondary"
                    size="small"
                    href={featuredArticle.href}
                    className="border-gray-300 text-gray-700 hover:bg-gray-100"
                  >
                    Learn more
                  </Button>
                </div>
              </div>
            </div>

            {/* Mobile Only - All News Button */}
            <div className="mt-6 md:hidden">
              <Button
                variant="secondary"
                href="/resources/news"
                className="w-full border-blue-600 text-blue-600 hover:bg-blue-50"
              >
                All news
              </Button>
            </div>
          </motion.div>

          {/* Other Articles */}
          <motion.div variants={cardVariants} className="space-y-6">
            {otherArticles.map((article, index) => (
              <div key={index} className="group cursor-pointer">
                <div className="bg-gray-50 rounded-xl p-6 hover:bg-gray-100 transition-colors">
                  {/* Category and Date */}
                  <div className="flex items-center justify-between mb-4">
                    <span
                      className="text-sm font-medium px-3 py-1 rounded-full"
                      style={{ color: article.categoryColor }}
                    >
                      {article.category}
                    </span>
                    <div className="flex items-center text-gray-500 text-sm">
                      <Calendar className="w-4 h-4 mr-1" />
                      {article.date}
                    </div>
                  </div>

                  {/* Title */}
                  <h3 className="text-lg font-semibold text-gray-900 group-hover:text-blue-600 transition-colors mb-4">
                    <a href={article.href}>
                      {article.title}
                    </a>
                  </h3>

                  {/* Read More Button */}
                  <Button
                    variant="secondary"
                    size="small"
                    href={article.href}
                    className="border-gray-300 text-gray-700 hover:bg-gray-100"
                  >
                    Learn more
                  </Button>
                </div>
              </div>
            ))}

            {/* Mobile Only - Products Button */}
            <div className="mt-6 md:hidden">
              <Button
                variant="secondary"
                href="/platform"
                className="w-full border-blue-600 text-blue-600 hover:bg-blue-50"
              >
                Our products
              </Button>
            </div>
          </motion.div>
        </motion.div>

        {/* Desktop Only - Bottom Buttons */}
        <motion.div
          className="hidden md:flex justify-center mt-12 space-x-6"
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          transition={{ duration: 0.6, delay: 0.4 }}
          viewport={{ once: true }}
        >
          <Button
            variant="secondary"
            href="/resources/news"
            className="border-blue-600 text-blue-600 hover:bg-blue-50"
          >
            All news
          </Button>
          <Button
            variant="secondary"
            href="/platform"
            className="border-blue-600 text-blue-600 hover:bg-blue-50"
          >
            Our products
          </Button>
        </motion.div>
      </div>
    </section>
  )
}

export default Resources
