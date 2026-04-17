import Button from "../ui/Button";
import { ArrowRight , Microchip } from "lucide-react";


interface CTASectionProps {
  onRegister: () => void;
  onLogin: () => void;
}

export function CTASection({ onRegister, onLogin }: CTASectionProps) {
  return (
    <section className="py-12 sm:py-20 bg-background relative overflow-hidden">
      <div className="absolute inset-0">
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-125 h-125 sm:w-200 sm:h-200 bg-[#1f6feb] rounded-full mix-blend-multiply filter blur-3xl opacity-10" />
      </div>

      <div className="absolute inset-0 opacity-5">
        <div
          className="w-full h-full"
          style={{
            backgroundImage: `linear-gradient(to right, #58a6ff 1px, transparent 1px), linear-gradient(to bottom, #58a6ff 1px, transparent 1px)`,
            backgroundSize: "80px 80px",
          }}
        />
      </div>

      <div className="container mx-auto px-4 sm:px-6 relative z-10">
        <div className="max-w-3xl mx-auto text-center">
          <div
            className="rs-glow inline-flex items-center justify-center w-14 h-14 sm:w-16 sm:h-16 rounded-2xl bg-surface-1 border border-[#30363d] mb-6"
            // style={{ "--rs-glow-color": "#58a6ff" }}
          >
            <Microchip className="w-7 h-7 sm:w-8 sm:h-8 text-[#58a6ff]" />
          </div>

          <h2 className="rs-text-glow text-3xl sm:text-4xl lg:text-5xl font-bold mb-4 sm:mb-6 text-white leading-tight">
            Ready to evaluate repositories smarter?
          </h2>

          <p className="text-base sm:text-xl text-[#8b949e] mb-8 leading-relaxed px-2 sm:px-0">
            Join thousands of developers making informed decisions about GitHub
            repositories. Start analyzing for free today.
          </p>

          {/* Buttons changed to stack nicely on mobile */}
          <div className="flex flex-col sm:flex-row gap-4 justify-center items-center w-full px-4 sm:px-0">
            <Button
              onClick={onRegister}
              className="bg-[#1f6feb] hover:bg-[#388bfd] text-white border-0 shadow-lg shadow-[#1f6feb]/30 group w-full sm:w-auto"
            >
              Get started for free
              <ArrowRight className="ml-2 w-5 h-5 group-hover:translate-x-1 transition-transform" />
            </Button>
            <Button
              onClick={onLogin}
              className="border-[#30363d] bg-surface-2 text-white hover:bg-surface-3 hover:border-[#58a6ff] w-full sm:w-auto"
            >
              Sign in
            </Button>
          </div>

          <p className="text-xs sm:text-sm text-[#8b949e] mt-8">
            No credit card required • Free forever • GitHub API integration
          </p>
        </div>
      </div>
    </section>
  );
}
