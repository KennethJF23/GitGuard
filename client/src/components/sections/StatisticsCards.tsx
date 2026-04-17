import { ShieldCheck, GitFork, Users2, CheckCircle2 } from "lucide-react";

function StatsSection() {
  const stats = [
    {
      icon: GitFork,
      value: "10,000+",
      label: "Repositories Analyzed",
      color: "#58a6ff",
    },
    { icon: Users2, value: "5,000+", label: "Active Users", color: "#3fb950" },
    {
      icon: ShieldCheck,
      value: "98%",
      label: "Security Accuracy",
      color: "#f0883e",
    },
    {
      icon: CheckCircle2,
      value: "15,000+",
      label: "Licenses Verified",
      color: "#a371f7",
    },
  ];

  return (
    <section className="py-10 sm:py-12 bg-background border-y border-[#30363d]">
      <div className="container mx-auto px-4 sm:px-6 lg:px-14">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-6 sm:gap-8">
          {stats.map((stat, index) => (
            <div key={index} className="text-center group">
              <div
                className="rs-glow inline-flex items-center justify-center w-12 h-12 sm:w-14 sm:h-14 rounded-lg bg-surface-1 border border-[#30363d] mb-3 sm:mb-4 group-hover:border-[#58a6ff] transition-all"
                // style={{ "--rs-glow-color": stat.color }}
              >
                <stat.icon
                  className="w-6 h-6 sm:w-7 sm:h-7"
                  style={{ color: stat.color }}
                />
              </div>
              <div className="rs-text-glow text-2xl sm:text-3xl font-bold text-white mb-1">
                {stat.value}
              </div>
              <div className="text-xs sm:text-sm text-[#8b949e]">
                {stat.label}
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

export default StatsSection;
