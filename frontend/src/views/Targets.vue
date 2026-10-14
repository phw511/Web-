<template>
  <div class="page">
    <div class="card">
      <h3>注册授权目标</h3>
      <input v-model="form.url" placeholder="http://target:port" size="40" />
      <input v-model="form.scope_paths" placeholder="范围路径,如 /" size="12" />
      <input v-model="form.q" placeholder="基准参数值 q" size="12" />
      <input v-model="form.justification" placeholder="授权依据" size="24" />
      <label><input type="checkbox" v-model="form.allow_private" /> 本地靶场(内网地址)</label>
      <button @click="submit">提交</button> <span style="color:#dc2626">{{ err }}</span>
    </div>
    <div class="card">
      <h3>目标列表</h3>
      <table><tr><th>URL</th><th>状态</th><th>提交人</th><th>有效期至</th><th>操作</th></tr>
      <tr v-for="t in targets" :key="t.id">
        <td>{{ t.url }}</td><td>{{ t.status }}</td><td>{{ t.submitted_by }}</td>
        <td>{{ (t.expires_at || '').slice(0, 10) }}</td>
        <td>
          <template v-if="t.status === 'pending' && role !== 'submitter'">
            <button @click="approve(t.id)">批准</button>
            <button style="background:#dc2626" @click="reject(t.id)">拒绝</button>
          </template>
        </td>
      </tr></table>
    </div>
  </div>
</template>
<script setup>
import { ref, onMounted, computed } from 'vue'
import { req, post } from '../api'
const role = computed(() => localStorage.getItem('role'))
const targets = ref([]), err = ref('')
const form = ref({ url: '', scope_paths: '/', q: '', justification: '', allow_private: false })
async function load() { targets.value = await req('/targets') }
async function submit() {
  err.value = ''
  try {
    await post('/targets', { url: form.value.url,
      scope_paths: form.value.scope_paths.split(','),
      base_params: form.value.q ? { q: form.value.q } : {},
      justification: form.value.justification,
      allow_private: form.value.allow_private })
    load()
  } catch (e) { err.value = e.message }
}
const reason = () => prompt('审批理由：') || ''
async function approve(id) { await post(`/targets/${id}/approve`, { reason: reason() }); load() }
async function reject(id) { await post(`/targets/${id}/reject`, { reason: reason() }); load() }
onMounted(load)
</script>
