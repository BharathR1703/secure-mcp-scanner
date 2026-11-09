import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// In Docker the frontend proxies to the `backend` service; locally the
// default http://localhost:8000 matches `uvicorn` on the host.
const backendUrl = process.env.BACKEND_URL || 'http://localhost:8000'
const proxy = {
  '/api': { target: backendUrl, changeOrigin: true },
}

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy,
  },
  preview: {
    host: true,
    port: 3000,
    proxy,
  },
})
