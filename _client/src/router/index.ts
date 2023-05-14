import { createRouter, createWebHistory  } from 'vue-router'

/** 常驻路由 */
export const constantRoutes = [
  {
    path: '/',
    component: () => import('@/views/login/login.vue'),
    // redirect: '/dashboard',
  },
]

const router = createRouter({
  history: createWebHistory(),
  routes: constantRoutes,
})

export default router
