import React from 'react'
import { ArrowRight } from 'lucide-react'
import cn from 'classnames'
import Link from 'next/link'

interface ButtonProps {
  children: React.ReactNode
  variant?: 'primary' | 'secondary' | 'white' | 'transparent'
  size?: 'small' | 'medium' | 'large'
  href?: string
  className?: string
  onClick?: () => void
  disabled?: boolean
}

const Button: React.FC<ButtonProps> = ({
  children,
  variant = 'primary',
  size = 'medium',
  href,
  className,
  onClick,
  disabled = false,
}) => {
  const baseClasses = 'inline-flex items-center justify-center font-medium rounded-lg transition-all duration-300 button-hover'
  
  const variantClasses = {
    primary: 'bg-blue-600 text-white hover:bg-blue-700',
    secondary: 'bg-transparent text-blue-600 border border-blue-600 hover:bg-blue-600 hover:text-white',
    white: 'bg-white text-blue-600 hover:bg-gray-100',
    transparent: 'bg-transparent text-white border border-white hover:bg-white hover:text-blue-600',
  }

  const sizeClasses = {
    small: 'px-4 py-2 text-sm',
    medium: 'px-6 py-3 text-base',
    large: 'px-8 py-4 text-lg',
  }

  const classes = cn(
    baseClasses,
    variantClasses[variant],
    sizeClasses[size],
    disabled && 'opacity-50 cursor-not-allowed',
    className
  )

  const content = (
    <>
      <span className="button-title">{children}</span>
      <ArrowRight className="ml-2 w-4 h-4 button-icon" />
    </>
  )

  if (href) {
    const isExternal = href.startsWith('http://') || href.startsWith('https://')

    if (isExternal) {
      return (
        <a href={href} className={classes}>
          {content}
        </a>
      )
    }

    return (
      <Link href={href} className={classes}>
        {content}
      </Link>
    )
  }

  return (
    <button
      className={classes}
      onClick={onClick}
      disabled={disabled}
    >
      {content}
    </button>
  )
}

export default Button
