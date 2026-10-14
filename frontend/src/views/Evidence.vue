<template>
  <div class="page"><div class="card">
    <h3>证据链回放</h3>
    <input v-model="scanId" placeholder="scan id" />
    <button @click="load">校验</button>
    <p v-if="chain">完整性：{{ chain.verified ? '✅ 哈希链校验通过' : '❌ 证据被篡改' }}
      （{{ chain.record_count }} 条记录）</p>
    <table v-if="chain"><tr><th>时序</th><th>类型</th><th>哈希</th></tr>
    <tr v-for="t in chain.timeline" :key="t.id">
      <td>{{ t.created_at }}</td><td>{{ t.kind }}</td>
      <td style="font-family:monospace">{{ t.hash.slice(0,16) }}…</td>
    </tr></table>
  </div></div>
</template>
<script setup>
import { ref } from 'vue'
import { req } from '../api'
const scanId = ref(''), chain = ref(null)
async function load() { chain.value = await req(`/evidence/${scanId.value}/chain`) }
</script>
