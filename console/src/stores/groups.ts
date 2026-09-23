import { defineStore } from 'pinia'
import { api, ApiError } from '@/api/client'
import type { components } from '@/api/schema'

export type Group = components['schemas']['Group']
export type GroupMember = components['schemas']['GroupMember']
export type EffectiveRole = components['schemas']['EffectiveRole']
export type UserGroupRef = components['schemas']['UserGroupRef']

/** Tenant groups: list, lifecycle, members and roles (admin API). */
export const useGroups = defineStore('groups', {
  state: () => ({ items: [] as Group[], loaded: false }),
  actions: {
    async load(q = ''): Promise<void> {
      try {
        const page = await api<{ items: Group[] }>('GET', '/api/v1/admin/groups', undefined, { query: { q: q || undefined } })
        this.items = page.items ?? []
      } catch (err) {
        if (!(err instanceof ApiError)) throw err
        this.items = []
      } finally {
        this.loaded = true
      }
    },
    async create(name: string, description: string): Promise<Group> {
      const g = await api<Group>('POST', '/api/v1/admin/groups', { name, description })
      this.items = [...this.items, g].sort((a, b) => (a.name ?? '').localeCompare(b.name ?? ''))
      return g
    },
    async update(id: string, name: string, description: string): Promise<Group> {
      const g = await api<Group>('PUT', `/api/v1/admin/groups/${encodeURIComponent(id)}`, { name, description })
      this.items = this.items.map((x) => (x.id === id ? g : x))
      return g
    },
    /** Deletion confirms the member count the administrator saw (FR-008). */
    async remove(id: string, memberCount: number): Promise<void> {
      await api('POST', `/api/v1/admin/groups/${encodeURIComponent(id)}/remove`, { member_count: memberCount })
      this.items = this.items.filter((x) => x.id !== id)
    },
    async get(id: string): Promise<Group> {
      return api<Group>('GET', `/api/v1/admin/groups/${encodeURIComponent(id)}`)
    },
    async members(id: string): Promise<GroupMember[]> {
      const page = await api<{ items: GroupMember[] }>('GET', `/api/v1/admin/groups/${encodeURIComponent(id)}/members`)
      return page.items
    },
    async addMembers(id: string, userIds: string[]): Promise<number> {
      const res = await api<{ added: number }>('POST', `/api/v1/admin/groups/${encodeURIComponent(id)}/members`, { user_ids: userIds })
      return res.added
    },
    async removeMember(id: string, userId: string): Promise<void> {
      await api('POST', `/api/v1/admin/groups/${encodeURIComponent(id)}/members/${encodeURIComponent(userId)}/remove`)
    },
    async setRoles(id: string, roleIds: string[]): Promise<string[]> {
      const res = await api<{ roles: string[] }>('PUT', `/api/v1/admin/groups/${encodeURIComponent(id)}/roles`, { role_ids: roleIds })
      return res.roles
    },
    async effectiveRoles(userId: string): Promise<EffectiveRole[]> {
      const page = await api<{ items: EffectiveRole[] }>('GET', `/api/v1/admin/users/${encodeURIComponent(userId)}/effective-roles`)
      return page.items
    },
    async userGroups(userId: string): Promise<UserGroupRef[]> {
      const page = await api<{ items: UserGroupRef[] }>('GET', `/api/v1/admin/users/${encodeURIComponent(userId)}/groups`)
      return page.items
    },
  },
})
