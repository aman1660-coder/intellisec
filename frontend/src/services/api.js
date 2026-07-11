import axios from "axios";

export const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000/api";

export const api = axios.create({
  baseURL: API_BASE,
  timeout: 30000
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem("intellisec_token");
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export const authApi = {
  register: (payload) => api.post("/auth/register", payload).then((res) => res.data),
  login: (payload) => api.post("/auth/login", payload).then((res) => res.data),
  me: () => api.get("/auth/me").then((res) => res.data)
};

export const scansApi = {
  create: (payload) => api.post("/scans", payload).then((res) => res.data),
  list: () => api.get("/scans").then((res) => res.data),
  get: (id) => api.get(`/scans/${id}`).then((res) => res.data),
  caseStudy: () => api.get("/case-study").then((res) => res.data)
};

