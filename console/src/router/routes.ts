import type { RouteRecordRaw } from 'vue-router'

declare module 'vue-router' {
  interface RouteMeta {
    /** No session required. */
    public?: boolean
    /** Any of these roles grants access (owner/admin always included). */
    roles?: string[]
    /** Platform operator only. */
    operator?: boolean
    layout?: 'default' | 'bare'
  }
}

// Story views register here; every protected route is also enforced server-side.
export const routes: RouteRecordRaw[] = [
  { path: '/', name: 'home', component: () => import('@/views/Home.vue') },
  { path: '/signin', name: 'signin', component: () => import('@/views/SignIn.vue'), meta: { public: true, layout: 'bare' } },
  { path: '/signin/mfa', name: 'signin-mfa', component: () => import('@/views/MfaChallenge.vue'), meta: { public: true, layout: 'bare' } },
  { path: '/recovery', name: 'recovery', component: () => import('@/views/Recovery.vue'), meta: { public: true, layout: 'bare' } },
  { path: '/security', name: 'security', component: () => import('@/views/Account.vue') },
  { path: '/security/enrol', name: 'mfa-enrol', component: () => import('@/views/MfaEnrol.vue'), meta: { layout: 'bare' } },
  { path: '/forgot', name: 'forgot', component: () => import('@/views/ForgotPassword.vue'), meta: { public: true, layout: 'bare' } },
  { path: '/reset', name: 'reset', component: () => import('@/views/ResetPassword.vue'), meta: { public: true, layout: 'bare' } },
  { path: '/sessions', name: 'sessions', component: () => import('@/views/Sessions.vue') },
  { path: '/invite/accept', name: 'invite-accept', component: () => import('@/views/AcceptInvitation.vue'), meta: { public: true, layout: 'bare' } },
  { path: '/admin/users', name: 'admin-users', component: () => import('@/views/admin/Users.vue'), meta: { roles: ['owner', 'admin'] } },
  { path: '/admin/users/:id', name: 'admin-user', component: () => import('@/views/admin/UserDetail.vue'), meta: { roles: ['owner', 'admin'] } },
  { path: '/admin/groups', name: 'admin-groups', component: () => import('@/views/admin/Groups.vue'), meta: { roles: ['owner', 'admin'] } },
  { path: '/admin/groups/:id', name: 'admin-group', component: () => import('@/views/admin/GroupDetail.vue'), meta: { roles: ['owner', 'admin'] } },
  { path: '/admin/roles', name: 'admin-roles', component: () => import('@/views/admin/Roles.vue'), meta: { roles: ['owner', 'admin'] } },
  { path: '/admin/roles/new', name: 'admin-role-new', component: () => import('@/views/admin/RoleEditor.vue'), meta: { roles: ['owner', 'admin'] } },
  { path: '/admin/roles/:id', name: 'admin-role', component: () => import('@/views/admin/RoleEditor.vue'), meta: { roles: ['owner', 'admin'] } },
  { path: '/admin/policy', name: 'admin-policy', component: () => import('@/views/admin/Policy.vue'), meta: { roles: ['owner', 'admin'] } },
  { path: '/admin/clients', name: 'admin-clients', component: () => import('@/views/admin/Clients.vue'), meta: { roles: ['owner', 'admin'] } },
  { path: '/operator/tenants', name: 'operator-tenants', component: () => import('@/views/operator/Tenants.vue'), meta: { operator: true } },
  { path: '/operator/tenants/:id', name: 'operator-tenant', component: () => import('@/views/operator/TenantDetail.vue'), meta: { operator: true } },
  { path: '/admin/audit', name: 'admin-audit', component: () => import('@/views/admin/Audit.vue'), meta: { roles: ['owner', 'admin', 'auditor'] } },
  { path: '/outage', name: 'outage', component: () => import('@/views/Outage.vue'), meta: { public: true, layout: 'bare' } },
  { path: '/forbidden', name: 'forbidden', component: () => import('@/views/Forbidden.vue') },
  { path: '/:pathMatch(.*)*', name: 'notfound', component: () => import('@/views/NotFound.vue'), meta: { public: true } },
]

