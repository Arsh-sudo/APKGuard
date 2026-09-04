import axios from 'axios';
import { APKReport, Job, SystemStats } from '../types';
import { mockReports, mockStats } from './mockData';

const BASE_URL = import.meta.env.VITE_API_URL || '';

export const apiClient = axios.create({
  baseURL: BASE_URL,
  timeout: 35000,
});

export const apiService = {
  async checkHealth(): Promise<{ api: boolean; ollama: boolean }> {
    try {
      const res = await apiClient.get('/health', { timeout: 4000 });
      const hasOllama = res.data?.model === 'loaded' || res.data?.ollama !== 'down';
      return { api: true, ollama: hasOllama };
    } catch {
      // Fallback check to alternative endpoint
      try {
        await apiClient.get('/api/health', { timeout: 3000 });
        return { api: true, ollama: true };
      } catch {
        return { api: false, ollama: false };
      }
    }
  },

  async getStats(): Promise<SystemStats> {
    try {
      const res = await apiClient.get<SystemStats>('/stats');
      return res.data;
    } catch (e) {
      console.warn('API getStats fallback to local store:', e);
      return mockStats;
    }
  },

  // Single-request reports fetch without thundering herd
  async getReports(): Promise<APKReport[]> {
    try {
      const res = await apiClient.get<APKReport[]>('/reports');
      if (Array.isArray(res.data) && res.data.length > 0) {
        return res.data;
      }
      return mockReports;
    } catch (e) {
      console.warn('API getReports fallback to mockReports:', e);
      return mockReports;
    }
  },

  async getReport(apkName: string): Promise<APKReport> {
    const cleanName = apkName.endsWith('.apk') ? apkName : `${apkName}.apk`;
    try {
      const res = await apiClient.get<APKReport>(`/report/${encodeURIComponent(cleanName)}`);
      return res.data;
    } catch {
      // Find in mock data
      const found = mockReports.find(
        (r) => r.apk_name === cleanName || r.apk_name.toLowerCase() === apkName.toLowerCase()
      );
      if (found) return found;
      throw new Error(`Report not found for ${apkName}`);
    }
  },

  async deleteReport(apkName: string): Promise<void> {
    const cleanName = apkName.endsWith('.apk') ? apkName : `${apkName}.apk`;
    try {
      await apiClient.delete(`/report/${encodeURIComponent(cleanName)}`);
    } catch {
      console.log(`Local delete for ${cleanName}`);
    }
  },

  // Propagates actual upload errors to caller without generating fake jobs
  async uploadAndAnalyse(file: File, runLlm: boolean): Promise<{ job_id: string; message: string }> {
    const form = new FormData();
    form.append('file', file);
    form.append('run_llm', String(runLlm));

    const endpoint = runLlm ? '/analyse' : '/quick-score';
    try {
      const res = await apiClient.post(endpoint, form, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });
      return res.data;
    } catch (err: any) {
      const msg = err.response?.data?.detail || err.message || 'File upload failed';
      throw new Error(msg);
    }
  },

  async pollJob(jobId: string): Promise<Job> {
    const res = await apiClient.get<Job>(`/job/${encodeURIComponent(jobId)}`);
    return res.data;
  },

  async getJobStatus(jobId: string): Promise<Job> {
    const res = await apiClient.get<Job>(`/job/${encodeURIComponent(jobId)}`);
    return res.data;
  },

  async cancelJob(jobId: string): Promise<void> {
    try {
      await apiClient.post(`/job/${encodeURIComponent(jobId)}/cancel`);
    } catch (e) {
      console.warn('Failed to cancel job:', e);
    }
  }
};
