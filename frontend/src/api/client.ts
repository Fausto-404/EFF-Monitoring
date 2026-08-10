import axios from 'axios';
import type { ReportFacets, ReportGenerateRequest, ReportGenerateResult, ReportRecord } from './types';

export const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || ''
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('eff_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('eff_token');
      window.location.reload();
    }
    return Promise.reject(error);
  }
);

export const reportApi = {
  listReports: async (params?: Record<string, unknown>) => (await api.get<ReportRecord[]>('/api/reports', { params })).data,
  getReportFacets: async () => (await api.get<ReportFacets>('/api/reports/facets')).data,
  getReport: async (id: number) => (await api.get<ReportRecord>(`/api/reports/${id}`)).data,
  createReport: async (payload: Partial<ReportRecord>) => (await api.post<ReportRecord>('/api/reports', payload)).data,
  generateReport: async (payload: ReportGenerateRequest) => (await api.post<ReportGenerateResult>('/api/reports/generate', payload)).data,
  updateReport: async (id: number, payload: Partial<ReportRecord>) => (await api.patch<ReportRecord>(`/api/reports/${id}`, payload)).data,
  deleteReport: async (id: number) => (await api.delete<{ ok: boolean }>(`/api/reports/${id}`)).data,
  duplicateReport: async (id: number) => (await api.post<ReportRecord>(`/api/reports/${id}/duplicate`)).data,
  getReportExportUrl: (id: number, format: 'md') => `/api/reports/${id}/export.${format}`
};
