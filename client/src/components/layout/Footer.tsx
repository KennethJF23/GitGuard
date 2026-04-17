'use client'

import React from 'react'
import { ArrowRight } from 'lucide-react'
import Image from 'next/image'

const Footer: React.FC = () => {
  const productCards = [
    {
      title: 'Protect',
      icon: 'envelope',
      href: '/products/mailinblack-spam-protection'
    },
    {
      title: 'Cyber Coach',
      icon: 'graduation-cap',
      href: '/products/mailinblack-phishing-simulation'
    },
    {
      title: 'Cyber Academy',
      icon: 'graduation-cap',
      href: '/products/mailinblack-cybersecurity-training'
    },
    {
      title: 'Sikker',
      icon: 'shield-keyhole',
      href: '/products/password-manager'
    }
  ]

  const footerLinks = {
    solutions: [
      { title: 'Anti spam', href: '/products/mailinblack-spam-protection/anti-spam-solution' },
      { title: 'Anti malware', href: '/products/mailinblack-spam-protection/anti-malware-solution' },
      { title: 'Anti ransomware', href: '/products/mailinblack-spam-protection/anti-ransomware-solution' },
      { title: 'Anti phishing', href: '/products/mailinblack-spam-protection/anti-phishing-solution' },
      { title: 'Anti spearphishing', href: '/products/mailinblack-spam-protection/anti-spearphishing-solution' },
      { title: 'Right to disconnect', href: '/products/mailinblack-spam-protection/right-to-disconnect' },
      { title: 'Audit of human vulnerabilities', href: '/products/mailinblack-phishing-simulation/audit-of-human-vulnerabilities' },
      { title: 'Phishing simulation', href: '/products/mailinblack-phishing-simulation/phishing-simulation' },
      { title: 'Ransomware simulation', href: '/products/mailinblack-phishing-simulation/ransomware-simulation' },
      { title: 'Cyber attacks simulation', href: '/products/mailinblack-phishing-simulation/cyberattacks-simulation' },
      { title: 'Password generator', href: '/password-generator' },
      { title: 'Password manager', href: '/products/password-manager' }
    ],
    mailinblack: [
      { title: 'News', href: '/resources/news' },
      { title: 'About us', href: '/company' },
      { title: 'Partners', href: '/partners' },
      { title: 'User area', href: 'https://app.mailinblack.com/#/login' },
      { title: 'Partners Area', href: 'https://qg.mailinblack.com/login' }
    ],
    contact: [
      { title: 'Jobs', href: 'https://carriere.mailinblack.com/' },
      { title: 'Request a demo', href: '/demonstration' },
      { title: 'Contact us', href: '/contact-us' },
      { title: 'Open a support ticket', href: '/open-a-support-ticket' }
    ]
  }

  const renderIcon = (iconName: string): React.ReactNode => {
    const iconMap: { [key: string]: React.ReactNode } = {
      'envelope': <i className="fa-solid fa-envelope" />,
      'graduation-cap': <i className="fa-solid fa-graduation-cap" />,
      'shield-keyhole': <i className="fa-solid fa-shield-keyhole" />
    }
    return iconMap[iconName] || null
  }

  return (
    <footer className="bg-black text-white pt-16 pb-8">
      <div className="container mx-auto px-4">
        {/* Product Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8 mb-16">
          {productCards.map((card, index) => (
            <div key={index} className="text-center group cursor-pointer">
              <div className="flex justify-center mb-4 space-x-2">
                {[...Array(3)].map((_, i) => (
                  <div key={i} className="text-blue-400 opacity-60 group-hover:opacity-100 transition-opacity">
                    {renderIcon(card.icon)}
                  </div>
                ))}
              </div>
              <a
                href={card.href}
                className="text-lg font-medium text-white hover:text-blue-400 transition-colors inline-flex items-center"
              >
                {card.title}
                <ArrowRight className="ml-2 w-4 h-4" />
              </a>
            </div>
          ))}
        </div>

        {/* Footer Links */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8 mb-12">
          {/* Solutions */}
          <div>
            <h3 className="text-sm font-semibold text-gray-300 uppercase mb-6">Solutions</h3>
            <ul className="space-y-3">
              {footerLinks.solutions.map((link, index) => (
                <li key={index}>
                  <a
                    href={link.href}
                    className="text-sm text-gray-400 hover:text-white transition-colors"
                  >
                    {link.title}
                  </a>
                </li>
              ))}
            </ul>
          </div>

          {/* GitGuard */}
          <div>
            <h3 className="text-sm font-semibold text-gray-300 uppercase mb-6">GitGuard</h3>
            <ul className="space-y-3">
              {footerLinks.mailinblack.map((link, index) => (
                <li key={index}>
                  <a
                    href={link.href}
                    className="text-sm text-gray-400 hover:text-white transition-colors"
                    target={link.href.includes('http') ? '_blank' : '_self'}
                    rel={link.href.includes('http') ? 'noopener noreferrer' : ''}
                  >
                    {link.title}
                  </a>
                </li>
              ))}
            </ul>
          </div>

          {/* Contact */}
          <div>
            <h3 className="text-sm font-semibold text-gray-300 uppercase mb-6">Contact</h3>
            <ul className="space-y-3">
              {footerLinks.contact.map((link, index) => (
                <li key={index}>
                  <a
                    href={link.href}
                    className="text-sm text-gray-400 hover:text-white transition-colors"
                    target={link.href.includes('http') ? '_blank' : '_self'}
                    rel={link.href.includes('http') ? 'noopener noreferrer' : ''}
                  >
                    {link.title}
                  </a>
                </li>
              ))}
            </ul>
          </div>
        </div>

        {/* Divider */}
        <div className="border-t border-gray-800 mb-8"></div>

        {/* Bottom Section */}
        <div className="flex flex-col md:flex-row justify-between items-center">
          {/* Logo */}
          <div className="mb-6 md:mb-0">
            <Image
              src="/logomailinblack2.webp"
              alt="GitGuard"
              width={200}
              height={40}
              className="h-10 w-auto opacity-80"
              onError={(e) => {
                const target = e.target as HTMLImageElement;
                target.style.display = 'none';
                const parent = target.parentElement;
                if (parent) {
                  parent.innerHTML = '<div class="text-lg font-semibold text-white">GitGuard</div>';
                }
              }}
            />
          </div>

          {/* Copyright */}
          <div className="text-sm text-gray-400 text-center">
            © 2024 GitGuard. All rights reserved.
          </div>
        </div>
      </div>
    </footer>
  )
}

export default Footer
