<template>
  <div class="page">
    <div class="card">
      <h3>发起扫描</h3>
      <select v-model="targetId">
        <option v-for="t in targets.filter(x => x.status === 'approved')" :key="t.id"
          :value="t.id">{{ t.url }}</option>
      </select>
      <button @click="run">执行检测→决策→攻击→复核</button>
      <pre v-if="result">{{ result }}</pre>
    </div>
    <div class="card" v-if="scanId">
      <h3>结论（状态机）</h3>
      <table><tr><th>候选</th><th>类型</th><th>参数</th><th>结论</th><th>证据等级</th><th>签署</th><th></th></tr>
      <tr v-for="c in conclusions" :key="c.id">
        <td>{{ c.candidate_id }}</td><td>{{ c.vuln_type }}</td><td>{{ c.parameter }}</td>
        <td><span class="badge" :class="'b-' + c.state">{{ c.state }}</span></td>
        <td>{{ c.evidence_level }}</td><td>{{ c.signed_by || '-' }}</td>
        <td><button v-if="!c.signed_by && ['CONFIRMED','REJECTED'].includes(c.state)"
             @click="sign(c.id)">签署</button></td>
      </tr></table>
      <a href="#" @click.prevent="dl('md')">导出 MD</a> ·
      <a href="#" @click.prevent="dl('html')">导出 HTML</a>
    </div>
  </div>
</template>
<script setup>
import { ref, onMounted } from 'vue'
import { req, post } from '../api'
const targets = ref([]), targetId = ref(''), result = ref(''), scanId = ref(''), conclusions = ref([])
async function load() { targets.value = await req('/targets') }
async function run() {
  result.value = JSON.stringify(await post('/scans', { target_id: targetId.value }), null, 2)
  scanId.value = JSON.parse(result.value).scan_id
  conclusions.value = await req('/conclusions?scan_id=' + scanId.value)
}
async function sign(id) {
  await post(`/conclusions/${id}/sign`, { note: prompt('签署意见：') || '已复核' })
  conclusions.value = await req('/conclusions?scan_id=' + scanId.value)
}
async function dl(fmt) {
  const r = await fetch(`/api/reports/${scanId.value}?format=${fmt}`,
    { headers: { Authorization: 'Bearer ' + localStorage.getItem('token') } })
  const a = document.createElement('a')
  a.href = URL.createObjectURL(await r.blob()); a.download = `report.${fmt}`; a.click()
}
onMounted(load)
</script>
