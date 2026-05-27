import axios from 'axios';

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
