'use client'

import React, { useState } from 'react'
import { ChevronDown, ArrowLeft, Menu, X, Globe } from 'lucide-react'
import Button from '../ui/Button'
import Image from 'next/image'

const Header: React.FC = () => {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)
  const [activeSubmenu, setActiveSubmenu] = useState<string | null>(null)

  const menuItems = [
    {
      title: 'Secure your organization',
      submenu: 'secure',
      items: [
        {
          title: 'U-Cyber 360°',
          description: 'The most comprehensive cybersecurity solution to reduce your human risks',
          icon: 'shield-halved',
          href: '/platform',
          large: true
        },
        {
          title: 'Protect',
          description: 'Email protection, essential in the fight against cyber attacks and spam',
          icon: 'envelope',
          href: '/products/mailinblack-spam-protection'
        },
        {
          title: 'Sikker',
          description: 'The simple, secure password manager for professionals',
          icon: 'lock',
          href: '/products/password-manager'
        },
        {
          title: 'Cyber Coach',
          description: 'Awareness via attack simulations, the pillar of your cybersecurity',
          icon: 'graduation-cap',
          href: '/products/mailinblack-phishing-simulation'
        },
        {
          title: 'Cyber Academy',
          description: 'Cybersecurity training via an interactive e-learning platform',
          icon: 'graduation-cap',
          href: '/products/mailinblack-cybersecurity-training'
        }
      ]
    },
    {
      title: 'Solutions',
      submenu: 'solutions',
      items: [
        {
          category: 'Cyber attack protection',
          links: [
            { title: 'Anti malware', href: '/products/mailinblack-spam-protection/anti-malware-solution' },
            { title: 'Anti phishing', href: '/products/mailinblack-spam-protection/anti-phishing-solution' },
            { title: 'Anti spearphishing', href: '/products/mailinblack-spam-protection/anti-spearphishing-solution' },
            { title: 'Anti ransomware', href: '/products/mailinblack-spam-protection/anti-ransomware-solution' }
          ]
        },
        {
          category: 'Security & Employee Tools',
          links: [
            { title: 'Anti spam', href: '/products/mailinblack-spam-protection/anti-spam-solution' },
            { title: 'Password manager', href: '/products/password-manager' },
            { title: 'Right to disconnect', href: '/products/mailinblack-spam-protection/right-to-disconnect' },
            { title: 'Password generator', href: '/password-generator' }
          ]
        },
        {
          category: 'Awareness & Training',
          links: [
            { title: 'Cybersecurity training', href: '/products/mailinblack-cybersecurity-training' },
            { title: 'Audit of human vulnerabilities', href: '/products/mailinblack-phishing-simulation/audit-of-human-vulnerabilities' },
            { title: 'Phishing simulation', href: '/products/mailinblack-phishing-simulation/phishing-simulation' },
            { title: 'Ransomware simulation', href: '/products/mailinblack-phishing-simulation/ransomware-simulation' }
          ]
        }
      ]
    },
    {
      title: 'Resources',
      submenu: 'resources',
      items: [
        { title: 'News', href: '/resources/news' },
        { title: 'Cybersecurity', href: '/expertises/cybersecurity' },
        { title: 'GDPR', href: '/expertises/gdpr' },
        { title: 'Product', href: '/expertises/product' },
        { title: 'Spam', href: '/expertises/spam-en' },
        { title: 'Well-Being', href: '/expertises/well-being' }
      ]
    },
    {
      title: 'GitGuard',
      submenu: 'mailinblack',
      items: [
        { title: 'Company', href: '/company' },
        { title: 'Mission', href: '/company/mission' }
      ]
    },
    {
      title: 'Partners',
      submenu: 'partners',
      items: [
        { title: 'Discover the program', href: '/partners' },
        { title: 'Partner area', href: 'https://partner.mailinblack.com/login', external: true }
      ]
    }
  ]

  const languages = [
    { code: 'en', name: 'English', active: true },
    { code: 'fr', name: 'Français' },
    { code: 'es', name: 'Español' },
    { code: 'nl', name: 'Nederlands' }
  ]

  const toggleSubmenu = (submenu: string) => {
    setActiveSubmenu(activeSubmenu === submenu ? null : submenu)
  }

  const renderIcon = (iconName: string): React.ReactNode => {
    const iconMap: { [key: string]: React.ReactNode } = {
      'shield-halved': <i className="fa-solid fa-shield-halved" />,
      'envelope': <i className="fa-solid fa-envelope" />,
      'lock': <i className="fa-solid fa-lock" />,
      'graduation-cap': <i className="fa-solid fa-graduation-cap" />,
      'globe': <i className="fa-solid fa-globe" />,
      'atom': <i className="fa-solid fa-atom" />,
      'database': <i className="fa-solid fa-database" />,
      'paper-plane': <i className="fa-solid fa-paper-plane" />,
      'at': <i className="fa-solid fa-at" />
    }
    return iconMap[iconName] || null
  }

  return (
    <header className="header bg-white shadow-sm relative z-50">
      <div className="container mx-auto px-4">
        <div className="flex items-center justify-between h-20">
          {/* Logo */}
          <a href="/" className="flex items-center">
            <Image
              src="/logomailinblack2.webp"
              alt="GitGuard"
              width={170}
              height={34}
              className="h-8 w-auto"
              onError={(e) => {
                const target = e.target as HTMLImageElement;
                target.style.display = 'none';
                const parent = target.parentElement;
                if (parent) {
                  parent.innerHTML = '<div class="text-2xl font-bold text-blue-600">GitGuard</div>';
                }
              }}
            />
          </a>

          {/* Desktop Navigation */}
          <nav className="hidden lg:flex items-center space-x-8">
            {menuItems.map((item) => (
              <div key={item.submenu} className="relative group">
                <button
                  className="flex items-center text-sm font-medium text-gray-700 hover:text-blue-600 transition-colors"
                  onMouseEnter={() => setActiveSubmenu(item.submenu)}
                  onMouseLeave={() => setActiveSubmenu(null)}
                >
                  {item.title}
                  <ChevronDown className="ml-1 w-4 h-4" />
                </button>

                {/* Dropdown Menu */}
                {activeSubmenu === item.submenu && (
                  <div
                    className="absolute top-full left-0 mt-2 w-96 bg-white rounded-lg shadow-xl border border-gray-200 p-6"
                    onMouseEnter={() => setActiveSubmenu(item.submenu)}
                    onMouseLeave={() => setActiveSubmenu(null)}
                  >
                    {item.submenu === 'secure' && (
                      <div className="space-y-4">
                        {item.items.map((subItem: any, index) => (
                          <div
                            key={index}
                            className={`p-4 rounded-lg border ${subItem.large ? 'col-span-2' : ''} hover:bg-gray-50 transition-colors`}
                          >
                            <div className="flex items-start space-x-3">
                              {subItem.icon && (
                                <div className="text-blue-600 mt-1">
                                  {renderIcon(subItem.icon)}
                                </div>
                              )}
                              <div className="flex-1">
                                <a
                                  href={subItem.href}
                                  className="font-medium text-gray-900 hover:text-blue-600 transition-colors"
                                >
                                  {subItem.title}
                                </a>
                                {subItem.description && (
                                  <p className="text-sm text-gray-600 mt-1">
                                    {subItem.description}
                                  </p>
                                )}
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}

                    {item.submenu === 'solutions' && (
                      <div className="grid grid-cols-3 gap-6">
                        {item.items.map((category: any, index) => (
                          <div key={index}>
                            <h4 className="font-semibold text-xs text-gray-600 uppercase mb-3">
                              {category.category}
                            </h4>
                            <ul className="space-y-2">
                              {category.links.map((link: any, linkIndex: number) => (
                                <li key={linkIndex}>
                                  <a
                                    href={link.href}
                                    className="text-sm text-gray-700 hover:text-blue-600 transition-colors"
                                  >
                                    {link.title}
                                  </a>
                                </li>
                              ))}
                            </ul>
                          </div>
                        ))}
                      </div>
                    )}

                    {item.submenu !== 'secure' && item.submenu !== 'solutions' && (
                      <ul className="space-y-2">
                        {item.items.map((subItem: any, index) => (
                          <li key={index}>
                            <a
                              href={subItem.href}
                              target={subItem.external ? '_blank' : '_self'}
                              rel={subItem.external ? 'noopener noreferrer' : ''}
                              className="text-sm text-gray-700 hover:text-blue-600 transition-colors"
                            >
                              {subItem.title}
                            </a>
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                )}
              </div>
            ))}
          </nav>

          {/* Right side items */}
          <div className="hidden lg:flex items-center space-x-6">
            {/* Language Selector */}
            <div className="relative group">
              <button className="flex items-center text-sm text-gray-700 hover:text-blue-600 transition-colors">
                <Globe className="w-4 h-4 mr-1" />
                English
                <ChevronDown className="ml-1 w-4 h-4" />
              </button>
              <div className="absolute top-full right-0 mt-2 w-32 bg-white rounded-lg shadow-xl border border-gray-200 py-2 opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all">
                {languages.map((lang) => (
                  <a
                    key={lang.code}
                    href={`/${lang.code}`}
                    className={`block px-4 py-2 text-sm ${
                      lang.active ? 'text-blue-600 bg-blue-50' : 'text-gray-700 hover:bg-gray-50'
                    } transition-colors`}
                  >
                    {lang.name}
                  </a>
                ))}
              </div>
            </div>

            {/* Help & User Area */}
            <a href="https://support.mailinblack.com/en/" className="text-sm text-gray-700 hover:text-blue-600 transition-colors">
              Help & support
            </a>
            <a href="https://app.mailinblack.com/#/login" className="text-sm text-gray-700 hover:text-blue-600 transition-colors">
              User area
            </a>

            {/* CTA Button */}
            <Button href="/demonstration" variant="primary" size="small">
              Request a demo
            </Button>
          </div>

          {/* Mobile Menu Button */}
          <button
            className="lg:hidden"
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
          >
            {mobileMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
          </button>
        </div>
      </div>

      {/* Mobile Menu */}
      {mobileMenuOpen && (
        <div className="lg:hidden bg-white border-t border-gray-200">
          <div className="container mx-auto px-4 py-4">
            {menuItems.map((item) => (
              <div key={item.submenu} className="mb-4">
                <button
                  className="flex items-center justify-between w-full text-left font-medium text-gray-900 py-2"
                  onClick={() => toggleSubmenu(item.submenu)}
                >
                  {item.title}
                  <ChevronDown className={`w-4 h-4 transition-transform ${activeSubmenu === item.submenu ? 'rotate-180' : ''}`} />
                </button>
                
                {activeSubmenu === item.submenu && (
                  <div className="mt-2 pl-4 space-y-2">
                    {item.items.map((subItem: any, index) => (
                      <a
                        key={index}
                        href={subItem.href}
                        className="block py-2 text-sm text-gray-700 hover:text-blue-600 transition-colors"
                      >
                        {subItem.title}
                      </a>
                    ))}
                  </div>
                )}
              </div>
            ))}
            
            <div className="pt-4 border-t border-gray-200 space-y-2">
              <Button href="/demonstration" variant="primary" size="small" className="w-full">
                Request a demo
              </Button>
            </div>
          </div>
        </div>
      )}
    </header>
  )
}

export default Header
