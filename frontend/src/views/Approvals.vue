<template>
  <div class="page"><div class="card">
    <h3>中高危攻击审批单</h3>
    <p v-if="!items.length">暂无待审批（低危函数由 Agent 自动放行并留痕）</p>
    <table v-else><tr><th>目标</th><th>类型</th><th>函数</th><th>风险</th><th>理由</th><th>操作</th></tr>
    <tr v-for="i in items" :key="i.decision_id">
      <td>{{ i.target_url }}</td><td>{{ i.vuln_type }}</td><td>{{ i.function_name }}</td>
      <td>{{ i.risk_level }}</td><td>{{ (i.reason || '').slice(0, 60) }}…</td>
      <td><button @click="decide(i.decision_id, 'approve')">批准执行</button>
          <button style="background:#dc2626" @click="decide(i.decision_id, 'reject')">否决</button></td>
    </tr></table>
    <p v-if="err" style="color:#dc2626">{{ err }}</p>
  </div></div>
</template>
<script setup>
import { ref, onMounted } from 'vue'
import { req, post } from '../api'
const items = ref([]), err = ref('')
async function load() { items.value = await req('/approvals/pending') }
async function decide(id, action) {
  err.value = ''
  // 后端要求审批理由非空（谁、何时、为什么放行），前端先挡一次，避免 400 往返
  const reason = (prompt('理由（必填）：') || '').trim()
  if (!reason) { err.value = '审批理由不能为空'; return }
  try { await post('/approvals', { decision_id: id, action, reason }); load() }
  catch (e) { err.value = e.message }
}
onMounted(load)
</script>
