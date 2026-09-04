import React from 'react';
import { useAppStore } from '../../lib/store';
import { AlertTriangle, CheckCircle2, Info, XCircle, X } from 'lucide-react';

export const ToastContainer: React.FC = () => {
  const { toasts, removeToast } = useAppStore();

  if (toasts.length === 0) return null;

  return (
    <div id="toast-container" className="fixed bottom-6 right-6 z-50 flex flex-col gap-2.5 max-w-md w-full pointer-events-none">
      {toasts.map((toast) => {
        const isError = toast.type === 'error';
        const isSuccess = toast.type === 'success';
        const isWarning = toast.type === 'warning';

        return (
          <div
            key={toast.id}
            id={`toast-${toast.id}`}
            className={`pointer-events-auto flex items-start justify-between gap-3 p-4 rounded-lg border backdrop-blur-md shadow-2xl transition-all duration-300 animate-in fade-in slide-in-from-bottom-5 ${
              isError
                ? 'bg-[#140b0d]/95 border-red-500/40 text-red-200'
                : isSuccess
                ? 'bg-[#0b1410]/95 border-emerald-500/40 text-emerald-200'
                : isWarning
                ? 'bg-[#14120b]/95 border-amber-500/40 text-amber-200'
                : 'bg-[#0d1017]/95 border-blue-500/40 text-blue-200'
            }`}
          >
            <div className="flex items-start gap-3">
              <span className="mt-0.5 shrink-0">
                {isError && <XCircle className="w-5 h-5 text-red-400" />}
                {isSuccess && <CheckCircle2 className="w-5 h-5 text-emerald-400" />}
                {isWarning && <AlertTriangle className="w-5 h-5 text-amber-400" />}
                {!isError && !isSuccess && !isWarning && <Info className="w-5 h-5 text-blue-400" />}
              </span>
              <div>
                <h4 className="text-sm font-semibold tracking-wide text-white font-sans">{toast.title}</h4>
                {toast.message && <p className="text-xs text-slate-400 mt-1 leading-relaxed">{toast.message}</p>}
                {toast.action && (
                  <button
                    id={`toast-btn-${toast.id}`}
                    onClick={toast.action.onClick}
                    className="mt-2 text-xs font-mono font-medium underline text-sky-400 hover:text-sky-300 transition-colors"
                  >
                    {toast.action.label}
                  </button>
                )}
              </div>
            </div>
            <button
              id={`toast-close-${toast.id}`}
              onClick={() => removeToast(toast.id)}
              className="text-slate-500 hover:text-slate-300 p-1 transition-colors"
              aria-label="Dismiss toast"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        );
      })}
    </div>
  );
};
