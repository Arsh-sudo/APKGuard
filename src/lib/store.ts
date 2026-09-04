import { create } from 'zustand';
import { APKReport, Job, SystemStats, ToastMessage, VerdictCategory } from '../types';
import { mockReports, mockStats } from './mockData';

interface AppState {
  // Reports
  reports: APKReport[];
  selectedReport: APKReport | null;
  stats: SystemStats;
  searchTerm: string;
  selectedCategory: VerdictCategory | 'ALL';
  
  // Pipeline & Job
  activeJob: Job | null;
  useLLM: boolean;
  isUploading: boolean;
  uploadProgress: number;

  // System Health
  apiOnline: boolean;
  ollamaOnline: boolean;
  lastHealthCheck: string | null;

  // Toasts
  toasts: ToastMessage[];

  // Actions
  setReports: (reports: APKReport[]) => void;
  addReport: (report: APKReport) => void;
  deleteReport: (apkName: string) => void;
  setSelectedReport: (report: APKReport | null) => void;
  setStats: (stats: SystemStats) => void;
  setSearchTerm: (term: string) => void;
  setSelectedCategory: (cat: VerdictCategory | 'ALL') => void;
  setActiveJob: (job: Job | null) => void;
  updateActiveJob: (partial: Partial<Job>) => void;
  setUseLLM: (val: boolean) => void;
  setIsUploading: (val: boolean) => void;
  setUploadProgress: (val: number) => void;
  setSystemHealth: (api: boolean, ollama: boolean) => void;
  addToast: (toast: Omit<ToastMessage, 'id'>) => void;
  removeToast: (id: string) => void;
}

export const useAppStore = create<AppState>((set, get) => ({
  reports: mockReports,
  selectedReport: null,
  stats: mockStats,
  searchTerm: '',
  selectedCategory: 'ALL',
  
  activeJob: null,
  useLLM: typeof window !== 'undefined' ? localStorage.getItem('apkguard_use_llm') !== 'false' : true,
  isUploading: false,
  uploadProgress: 0,

  apiOnline: true,
  ollamaOnline: true,
  lastHealthCheck: null,

  toasts: [],

  setReports: (reports) => set({ reports }),
  addReport: (report) => set((state) => {
    const filtered = state.reports.filter(r => r.apk_name !== report.apk_name);
    return { reports: [report, ...filtered] };
  }),
  deleteReport: (apkName) => set((state) => {
    const reports = state.reports.filter(r => r.apk_name !== apkName && !r.apk_name.startsWith(apkName));
    const selectedReport = state.selectedReport?.apk_name === apkName ? null : state.selectedReport;
    return { reports, selectedReport };
  }),
  setSelectedReport: (report) => set({ selectedReport: report }),
  setStats: (stats) => set({ stats }),
  setSearchTerm: (searchTerm) => set({ searchTerm }),
  setSelectedCategory: (selectedCategory) => set({ selectedCategory }),
  setActiveJob: (activeJob) => set({ activeJob }),
  updateActiveJob: (partial) => set((state) => ({
    activeJob: state.activeJob ? { ...state.activeJob, ...partial } : null
  })),
  setUseLLM: (useLLM) => {
    if (typeof window !== 'undefined') {
      localStorage.setItem('apkguard_use_llm', String(useLLM));
    }
    set({ useLLM });
  },
  setIsUploading: (isUploading) => set({ isUploading }),
  setUploadProgress: (uploadProgress) => set({ uploadProgress }),
  setSystemHealth: (apiOnline, ollamaOnline) => set({ apiOnline, ollamaOnline, lastHealthCheck: new Date().toISOString() }),

  addToast: (toast) => {
    const id = Math.random().toString(36).substring(2, 9);
    const newToast: ToastMessage = { ...toast, id };
    set((state) => ({ toasts: [...state.toasts, newToast] }));
    const duration = toast.duration ?? 4500;
    if (duration > 0) {
      setTimeout(() => {
        get().removeToast(id);
      }, duration);
    }
  },
  removeToast: (id) => set((state) => ({
    toasts: state.toasts.filter((t) => t.id !== id)
  }))
}));
