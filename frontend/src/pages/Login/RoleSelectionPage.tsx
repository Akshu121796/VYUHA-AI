import React, { useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Shield, Crown, Terminal } from "lucide-react";
import { useAuth } from "../../hooks/useAuth";
import { Button } from "../../components/ui/Button";
import { motion } from "framer-motion";

export function RoleSelectionPage() {
  const navigate = useNavigate();
  const { isAuthenticated } = useAuth();

  useEffect(() => {
    if (isAuthenticated) {
      navigate("/");
    }
  }, [isAuthenticated, navigate]);

  const containerVariants = {
    hidden: { opacity: 0, y: 15 },
    show: {
      opacity: 1,
      y: 0,
      transition: {
        duration: 0.4,
        ease: [0.16, 1, 0.3, 1],
        staggerChildren: 0.1
      }
    }
  };

  const itemVariants = {
    hidden: { opacity: 0, y: 15 },
    show: { 
      opacity: 1, 
      y: 0,
      transition: { duration: 0.4, ease: [0.16, 1, 0.3, 1] } 
    }
  };

  return (
    <div className="relative min-h-screen w-full flex items-center justify-center bg-slate-50 dark:bg-[#0b1220] p-6 transition-colors duration-300 select-none">
      {/* Background grid */}
      <div className="absolute inset-0 cyber-grid-overlay opacity-5 pointer-events-none" />
      
      {/* Glow ambient background */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[450px] h-[450px] bg-blue-650/[0.04] dark:bg-blue-650/[0.07] blur-[140px] rounded-full pointer-events-none" />

      <motion.div 
        variants={containerVariants}
        initial="hidden"
        animate="show"
        className="relative z-10 w-full max-w-3xl flex flex-col items-center"
      >
        {/* Logo */}
        <motion.div variants={itemVariants} className="flex items-center gap-2.5 mb-2">
          <div className="flex h-10 w-10 items-center justify-center rounded-2xl border border-blue-500 bg-blue-600 text-white shadow-md">
            <Shield className="h-5 w-5" />
          </div>
          <span className="text-xl font-bold tracking-tight text-slate-900 dark:text-white font-sans">
            VYUHA<span className="text-blue-500">.AI</span>
          </span>
        </motion.div>
        <motion.p variants={itemVariants} className="text-[10px] font-mono font-bold tracking-[0.25em] text-slate-400 dark:text-slate-500 uppercase mb-8">
          enterprise security operations console
        </motion.p>

        {/* Title */}
        <motion.h1 variants={itemVariants} className="text-2xl sm:text-3xl font-extrabold tracking-tight text-slate-900 dark:text-white font-sans text-center">
          Welcome to VYUHA.AI
        </motion.h1>
        <motion.p variants={itemVariants} className="mt-2 text-sm text-slate-500 dark:text-slate-400 font-sans text-center max-w-md">
          Select how you want to access the platform.
        </motion.p>

        {/* Cards container */}
        <motion.div variants={itemVariants} className="mt-10 grid grid-cols-1 md:grid-cols-2 gap-6 w-full">
          {/* Card 1: Admin */}
          <div 
            onClick={() => navigate("/admin-login")}
            className="group cursor-pointer rounded-[24px] border border-slate-200/80 bg-white/90 p-8 shadow-sm dark:border-slate-800 dark:bg-[#111827]/90 transition-all duration-300 ease-out hover:-translate-y-1.5 hover:shadow-xl hover:border-blue-500/50 hover:bg-blue-50/10 dark:hover:bg-blue-950/10 flex flex-col justify-between h-[320px] relative overflow-hidden"
          >
            {/* Subtle card glow overlay on hover */}
            <div className="absolute inset-0 bg-gradient-to-br from-blue-500/0 to-blue-500/[0.02] opacity-0 group-hover:opacity-100 transition-opacity duration-300 pointer-events-none" />
            
            <div className="space-y-4 relative z-10">
              <div className="flex h-14 w-14 items-center justify-center rounded-2xl border border-blue-100 bg-blue-50 text-blue-600 dark:border-blue-900/30 dark:bg-blue-950/20 dark:text-blue-400 shadow-sm transition-all duration-300 group-hover:scale-105 group-hover:bg-blue-600 group-hover:text-white group-hover:border-blue-600">
                <Crown className="h-6 w-6" />
              </div>
              <h2 className="text-lg font-bold text-slate-950 dark:text-white font-sans flex items-center gap-1.5 pt-2">
                👑 Administrator
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400 font-sans leading-relaxed">
                Manage endpoints, approve remediations, configure security policies and monitor the entire organization.
              </p>
            </div>
            <Button 
              variant="default"
              size="lg"
              className="mt-6 w-full text-xs font-semibold h-10 tracking-wide rounded-xl pointer-events-none group-hover:bg-blue-700 transition-colors relative z-10"
            >
              Continue as Administrator
            </Button>
          </div>

          {/* Card 2: Analyst */}
          <div 
            onClick={() => navigate("/analyst-login")}
            className="group cursor-pointer rounded-[24px] border border-slate-200/80 bg-white/90 p-8 shadow-sm dark:border-slate-800 dark:bg-[#111827]/90 transition-all duration-300 ease-out hover:-translate-y-1.5 hover:shadow-xl hover:border-purple-500/50 hover:bg-purple-50/10 dark:hover:bg-purple-950/10 flex flex-col justify-between h-[320px] relative overflow-hidden"
          >
            {/* Subtle card glow overlay on hover */}
            <div className="absolute inset-0 bg-gradient-to-br from-purple-500/0 to-purple-500/[0.02] opacity-0 group-hover:opacity-100 transition-opacity duration-300 pointer-events-none" />
            
            <div className="space-y-4 relative z-10">
              <div className="flex h-14 w-14 items-center justify-center rounded-2xl border border-purple-100 bg-purple-50 text-purple-600 dark:border-purple-900/30 dark:bg-purple-950/20 dark:text-purple-400 shadow-sm transition-all duration-300 group-hover:scale-105 group-hover:bg-purple-600 group-hover:text-white group-hover:border-purple-600">
                <Shield className="h-6 w-6" />
              </div>
              <h2 className="text-lg font-bold text-slate-950 dark:text-white font-sans flex items-center gap-1.5 pt-2">
                🛡 Security Analyst
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400 font-sans leading-relaxed">
                Investigate alerts, analyze attack routes, review weaknesses and interact with the AI Security Copilot.
              </p>
            </div>
            <Button 
              variant="neutral"
              size="lg"
              className="mt-6 w-full text-xs font-semibold h-10 tracking-wide rounded-xl pointer-events-none group-hover:bg-purple-600 group-hover:text-white group-hover:border-purple-600 transition-all relative z-10"
            >
              Continue as Analyst
            </Button>
          </div>
        </motion.div>

        {/* Footer */}
        <motion.div variants={itemVariants} className="flex items-center gap-1.5 text-[10px] text-slate-400 dark:text-slate-500 font-mono mt-16">
          <Terminal className="h-3.5 w-3.5" />
          <span>VYUHA SOC DISPATCHER // MULTI-ROUTING GATEWAY</span>
        </motion.div>
      </motion.div>
    </div>
  );
}

export default RoleSelectionPage;
