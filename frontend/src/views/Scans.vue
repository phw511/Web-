<template>
  <div class="page">
    <div class="card">
      <h3>发起扫描</h3>
      <select v-model="targetId">
        <option v-for="t in targets.filter(x => x.status === 'approved')" :key="t.id"
          :value="t.id">{{ t.url }}</option>
      </select>
      <button @click="run" :disabled="!targetId">执行检测→决策→攻击→复核</button>
      <pre v-if="result">{{ result }}</pre>
      <p v-if="err" style="color:#dc2626">{{ err }}</p>
    </div>
    <div class="card" v-if="scanId">
      <h3>结论（状态机）</h3>
      <table><tr><th>候选</th><th>类型</th><th>参数</th><th>结论</th><th>证据等级</th><th>签署</th><th></th></tr>
      <tr v-for="c in conclusions" :key="c.id">
        <td>{{ c.candidate_id }}</td><td>{{ c.vuln_type }}</td><td>{{ c.parameter }}</td>
        <td><span class="badge" :class="'b-' + c.state">{{ c.state }}</span></td>
        <td>{{ c.evidence_level }}</td><td>{{ c.signed_by || '-' }}</td>
        <td><button v-if="canSign && !c.signed_by && ['CONFIRMED','REJECTED'].includes(c.state)"
             @click="sign(c.id)">签署</button></td>
      </tr></table>
      <a href="#" @click.prevent="dl('md')">导出 MD</a> ·
      <a href="#" @click.prevent="dl('html')">导出 HTML</a>
    </div>
  </div>
</template>
<script setup>
import { ref, onMounted, computed } from 'vue'
import { req, post } from '../api'
const targets = ref([]), targetId = ref(''), result = ref(''), scanId = ref('')
const conclusions = ref([]), err = ref('')
const role = computed(() => localStorage.getItem('role'))
// 只有 signer/admin 显示签署按钮（INCONCLUSIVE 不可签署，由后端强制）
const canSign = computed(() => ['signer', 'admin'].includes(role.value))
async function load() { targets.value = await req('/targets') }
async function run() {
  err.value = ''
  try {
    const r = await post('/scans', { target_id: targetId.value })
    result.value = JSON.stringify(r, null, 2)
    scanId.value = r.scan_id
    conclusions.value = await req('/conclusions?scan_id=' + scanId.value)
  } catch (e) { err.value = e.message }
}
async function sign(id) {
  const note = prompt('签署意见：') || ''
  if (!note.trim()) { err.value = '签署必须填写意见'; return }
  try {
    await post(`/conclusions/${id}/sign`, { note })
    conclusions.value = await req('/conclusions?scan_id=' + scanId.value)
  } catch (e) { err.value = e.message }
}
async function dl(fmt) {
  const r = await fetch(`/api/reports/${scanId.value}?format=${fmt}`,
    { headers: { Authorization: 'Bearer ' + localStorage.getItem('token') } })
  if (!r.ok) { err.value = '导出失败：' + r.status; return }
  const a = document.createElement('a')
  a.href = URL.createObjectURL(await r.blob()); a.download = `report.${fmt}`; a.click()
}
onMounted(load)
</script>
