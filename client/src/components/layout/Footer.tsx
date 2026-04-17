import { Microchip } from "lucide-react";
import Image from "next/image";


export function Footer() {
  return (
    <footer className="bg-surface-1 text-[#8b949e] pt-8 px-3 sm:pt-12 pb-8 border-t border-[#30363d]">
      <div className="container mx-auto px-0 sm:px-4 ">
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-5 gap-10 sm:gap-12 mb-12">
          {/* Brand */}
          <div className="sm:col-span-2 md:col-span-2">
            <div className="flex items-center gap-2 mb-4">
              <Image
                src="/images/Hero_Image.png"
                alt="GitGuard Logo"
                width={40}
                height={40}
              />
              <span className="rs-text-glow font-bold text-xl text-white">GitGuard</span>
            </div>
            <p className="text-sm sm:text-base text-[#8b949e] mb-6 max-w-sm leading-relaxed">
              Making GitHub repositories safer and more reliable for everyone.
              Evaluate repositories with confidence using our comprehensive
              analysis tools.
            </p>
            <div className="flex flex-wrap gap-3">
              <a
                href="#github"
                className="w-10 h-10 rounded-lg bg-surface-2 border border-[#30363d] flex items-center justify-center hover:border-[#58a6ff] hover:bg-background transition-all"
              >
                <Microchip className="w-5 h-5" />
              </a>
              <a
                href="#twitter"
                className="w-10 h-10 rounded-lg bg-surface-2 border border-[#30363d] flex items-center justify-center hover:border-[#58a6ff] hover:bg-background transition-all"
              >
                <Microchip className="w-5 h-5" />
              </a>
              <a
                href="#linkedin"
                className="w-10 h-10 rounded-lg bg-surface-2 border border-[#30363d] flex items-center justify-center hover:border-[#58a6ff] hover:bg-background transition-all"
              >
                <Microchip className="w-5 h-5" />
              </a>
              <a
                href="#email"
                className="w-10 h-10 rounded-lg bg-surface-2 border border-[#30363d] flex items-center justify-center hover:border-[#58a6ff] hover:bg-background transition-all"
              >
                <Microchip className="w-5 h-5" />
              </a>
            </div>
          </div>

          {/* Links */}
          <div>
            <h3 className="font-semibold text-white mb-4">Product</h3>
            <ul className="space-y-3 text-sm">
              <li>
                <a
                  href="#features"
                  className="hover:text-[#58a6ff] transition-colors"
                >
                  Features
                </a>
              </li>
              <li>
                <a
                  href="#how-it-works"
                  className="hover:text-[#58a6ff] transition-colors"
                >
                  How It Works
                </a>
              </li>
              <li>
                <a
                  href="#pricing"
                  className="hover:text-[#58a6ff] transition-colors"
                >
                  Pricing
                </a>
              </li>
              <li>
                <a
                  href="#api"
                  className="hover:text-[#58a6ff] transition-colors"
                >
                  API
                </a>
              </li>
            </ul>
          </div>

          <div>
            <h3 className="font-semibold text-white mb-4">Resources</h3>
            <ul className="space-y-3 text-sm">
              <li>
                <a
                  href="#docs"
                  className="hover:text-[#58a6ff] transition-colors"
                >
                  Documentation
                </a>
              </li>
              <li>
                <a
                  href="#blog"
                  className="hover:text-[#58a6ff] transition-colors"
                >
                  Blog
                </a>
              </li>
              <li>
                <a
                  href="#guides"
                  className="hover:text-[#58a6ff] transition-colors"
                >
                  Guides
                </a>
              </li>
              <li>
                <a
                  href="#support"
                  className="hover:text-[#58a6ff] transition-colors"
                >
                  Support
                </a>
              </li>
            </ul>
          </div>

          <div>
            <h3 className="font-semibold text-white mb-4">Company</h3>
            <ul className="space-y-3 text-sm">
              <li>
                <a
                  href="#about"
                  className="hover:text-[#58a6ff] transition-colors"
                >
                  About
                </a>
              </li>
              <li>
                <a
                  href="#team"
                  className="hover:text-[#58a6ff] transition-colors"
                >
                  Team
                </a>
              </li>
              <li>
                <a
                  href="#careers"
                  className="hover:text-[#58a6ff] transition-colors"
                >
                  Careers
                </a>
              </li>
              <li>
                <a
                  href="#contact"
                  className="hover:text-[#58a6ff] transition-colors"
                >
                  Contact
                </a>
              </li>
            </ul>
          </div>
        </div>

        {/* Bottom Bar - Enabled flex-wrap for mobile */}
        <div className="pt-8 border-t border-[#30363d] flex flex-col md:flex-row justify-between items-center gap-4 text-xs sm:text-sm">
          <p className="text-center md:text-left">
            © 2026 GitGuard. All rights reserved.
          </p>
          <div className="flex flex-wrap justify-center gap-4 sm:gap-6">
            <a
              href="#privacy"
              className="hover:text-[#58a6ff] transition-colors"
            >
              Privacy
            </a>
            <a href="#terms" className="hover:text-[#58a6ff] transition-colors">
              Terms
            </a>
            <a
              href="#security"
              className="hover:text-[#58a6ff] transition-colors"
            >
              Security
            </a>
            <a
              href="#cookies"
              className="hover:text-[#58a6ff] transition-colors"
            >
              Cookies
            </a>
          </div>
        </div>
      </div>
    </footer>
  );
}

export default Footer;
