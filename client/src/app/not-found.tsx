"use client";

import Link from 'next/link';
import { FileQuestion, Home, ArrowLeft } from 'lucide-react';

export default function NotFound() {
  return (
    <div className="min-h-screen bg-background flex flex-col items-center justify-center p-4 text-[#c9d1d9] font-sans">
      <div className="max-w-md w-full text-center space-y-6">
        
        {/* Icon / Graphic */}
        <div className="relative flex justify-center">
          {/* Subtle blue glow behind the icon */}
          <div className="absolute inset-0 bg-[#58a6ff] blur-3xl opacity-10 rounded-full w-32 h-32 mx-auto"></div>
          
          <div className="w-24 h-24 bg-surface-1 border border-[#30363d] rounded-2xl flex items-center justify-center relative z-10 shadow-lg">
            <FileQuestion className="w-12 h-12 text-[#8b949e]" />
          </div>
        </div>

        {/* Text Content */}
        <div className="space-y-3">
          <h1 className="rs-text-glow text-5xl md:text-6xl font-bold text-white tracking-tight">404</h1>
          <h2 className="rs-text-glow text-xl md:text-2xl font-semibold text-white">Page not found</h2>
          <p className="text-[#8b949e] text-sm md:text-base px-2">
            Oops! Looks like the branch you&apos;re looking for doesn&apos;t exist, or the repository might have been deleted.
          </p>
        </div>

        {/* Action Buttons */}
        <div className="flex flex-col sm:flex-row items-center justify-center gap-3 pt-4">
          <Link 
            href="/" 
            className="w-full sm:w-auto flex items-center justify-center px-6 py-2.5 bg-[#1f6feb] hover:bg-[#388bfd] text-white rounded-md font-medium transition-colors border border-[rgba(240,246,252,0.1)] shadow-lg shadow-[#1f6feb]/20"
          >
            <Home className="w-4 h-4 mr-2" />
            Return Home
          </Link>
          <button 
            onClick={() => window.history.back()}
            className="w-full sm:w-auto flex items-center justify-center px-6 py-2.5 bg-surface-2 hover:bg-surface-3 border border-[#30363d] hover:border-[#8b949e] text-[#c9d1d9] rounded-md font-medium transition-colors"
          >
            <ArrowLeft className="w-4 h-4 mr-2" />
            Go Back
          </button>
        </div>
        
        {/* Decorative footer text */}
        <div className="pt-10 text-xs text-[#6e7681] font-mono">
          System check: <span className="text-[#58a6ff]">RepoSmart_404_Error</span>
        </div>
        
      </div>
    </div>
  );
}