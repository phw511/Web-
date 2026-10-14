<template>
  <nav v-if="$route.path !== '/login'">
    <b>WebVuln</b>
    <router-link to="/targets">目标</router-link>
    <router-link to="/scans">扫描</router-link>
    <router-link to="/approvals">审批</router-link>
    <router-link to="/evidence">证据</router-link>
    <span class="sp"></span>
    <span>{{ role }}</span><a href="#" @click.prevent="logout">退出</a>
  </nav>
  <router-view />
</template>
<script setup>
import { computed } from 'vue'
const role = computed(() => localStorage.getItem('role') || '')
function logout() { localStorage.clear(); location.href = '/login' }
</script>
<style>
nav { display: flex; gap: 14px; align-items: center; padding: 10px 16px;
  background: #1f2937; color: #fff; }
nav a { color: #cbd5e1; text-decoration: none; } nav .sp { flex: 1 }
body { margin: 0; font-family: system-ui; background: #f8fafc; color: #111827; }
table { border-collapse: collapse; width: 100%; background: #fff; }
td, th { border: 1px solid #e5e7eb; padding: 6px 10px; font-size: 14px; text-align: left; }
button { padding: 6px 14px; border: 0; border-radius: 6px; background: #2563eb;
  color: #fff; cursor: pointer; }
input, select { padding: 6px 8px; border: 1px solid #d1d5db; border-radius: 6px; margin: 2px; }
.page { padding: 20px; } .card { background: #fff; border: 1px solid #e5e7eb;
  border-radius: 8px; padding: 16px; margin-bottom: 16px; }
.badge { padding: 2px 8px; border-radius: 10px; font-size: 12px; background: #e5e7eb; }
.b-CONFIRMED { background: #dcfce7; } .b-REJECTED { background: #fee2e2; }
.b-INCONCLUSIVE { background: #fef9c3; }
</style>
