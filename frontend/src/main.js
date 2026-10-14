import { createApp } from 'vue'
import { createRouter, createWebHistory } from 'vue-router'
import App from './App.vue'
import Login from './views/Login.vue'
import Targets from './views/Targets.vue'
import Scans from './views/Scans.vue'
import Approvals from './views/Approvals.vue'
import Evidence from './views/Evidence.vue'

const routes = [
  { path: '/login', component: Login },
  { path: '/targets', component: Targets },
  { path: '/scans', component: Scans },
  { path: '/approvals', component: Approvals },
  { path: '/evidence', component: Evidence },
]
const router = createRouter({ history: createWebHistory(), routes })
router.beforeEach((to) => {
  if (to.path !== '/login' && !localStorage.getItem('token')) return '/login'
})
createApp(App).use(router).mount('#app')
