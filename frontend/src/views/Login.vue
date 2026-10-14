<template>
  <div class="page" style="max-width:360px;margin:80px auto">
    <div class="card">
      <h3>登录</h3>
      <input v-model="u" placeholder="用户名" /><br/>
      <input v-model="p" type="password" placeholder="密码" /><br/><br/>
      <button @click="login">登录</button>
      <p style="color:#dc2626">{{ err }}</p>
    </div>
  </div>
</template>
<script setup>
import { ref } from 'vue'
import { post } from '../api'
const u = ref(''), p = ref(''), err = ref('')
async function login() {
  try {
    const r = await post('/auth/login', { username: u.value, password: p.value })
    localStorage.setItem('token', r.token); localStorage.setItem('role', r.role)
    location.href = '/targets'
  } catch (e) { err.value = e.message }
}
</script>
