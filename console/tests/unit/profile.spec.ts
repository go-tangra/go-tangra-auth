import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import ProfileForm from '@/components/ProfileForm.vue'
import AvatarEditor from '@/components/AvatarEditor.vue'
import Account from '@/views/Account.vue'
import { SESSION_CHANGED_EVENT, useSession } from '@/stores/session'
import { mountView, stubFetch } from './helpers'

const profile = { id: 'u1', email: 'dana@x.test', display_name: 'Dana Kovač', first_name: 'Dana', last_name: 'Kovač', phone: '+385911234567', avatar_url: '', updated_at: null }

describe('profile', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    URL.createObjectURL = () => 'blob:x'
    URL.revokeObjectURL = () => undefined
  })

  it('loads, validates and saves the profile; the display name is sent only when overridden', async () => {
    const fetch = stubFetch((url, init) => {
      if (url === '/api/v1/me/profile' && init?.method === 'PUT') return { status: 200, body: { ...profile, phone: '+385911234567' } }
      return { status: 200, body: profile }
    })
    const w = mountView(ProfileForm, { profilePath: '/api/v1/me/profile', avatarUploadPath: '/api/v1/me/avatar', avatarRemovePath: '/api/v1/me/avatar' })
    await flushPromises()
    expect((w.find('[data-test="first-name"] input').element as HTMLInputElement).value).toBe('Dana')
    await w.find('[data-test="phone"] input').setValue('abc')
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(fetch).not.toHaveBeenCalledWith('/api/v1/me/profile', expect.objectContaining({ method: 'PUT' }))
    await w.find('[data-test="phone"] input').setValue('+385 91 123 4567')
    await w.find('form').trigger('submit')
    await flushPromises()
    const call = vi.mocked(fetch).mock.calls.find((c) => (c[1] as RequestInit)?.method === 'PUT')!
    expect(JSON.parse(String((call[1] as RequestInit).body))).toEqual({ first_name: 'Dana', last_name: 'Kovač', phone: '+385 91 123 4567' })
    expect(w.find('[data-test="profile-saved"]').exists()).toBe(true)
    expect(w.findComponent(ProfileForm).emitted('changed')).toBeTruthy()
  })

  it('refuses unsupported or oversized files before uploading, uploads valid ones with the CSRF header, removes', async () => {
    document.cookie = '__Host-csrf=tok123; Secure; Path=/'
    const fetch = stubFetch((url, init) => {
      if (url === '/api/v1/me/avatar' && init?.method === 'PUT') return { status: 200, body: { avatar_url: '/api/v1/users/u1/avatar/abc' } }
      return { status: 204, body: null }
    })
    const w = mountView(AvatarEditor, { modelValue: '', name: 'Dana Kovač', uploadPath: '/api/v1/me/avatar', removePath: '/api/v1/me/avatar' })
    expect(w.find('[data-test="avatar-preview"]').text()).toBe('DK')
    const input = w.find('[data-test="avatar-file"]').element as HTMLInputElement
    const feed = async (file: File) => {
      Object.defineProperty(input, 'files', { value: [file], configurable: true })
      await w.find('[data-test="avatar-file"]').trigger('change')
      await flushPromises()
    }
    await feed(new File(['<svg/>'], 'x.svg', { type: 'image/svg+xml' }))
    expect(w.find('[data-test="avatar-error"]').text()).toContain('PNG, JPEG or WebP')
    expect(fetch).not.toHaveBeenCalled()
    await feed(new File([new Uint8Array(3 * 1024 * 1024)], 'big.png', { type: 'image/png' }))
    expect(w.find('[data-test="avatar-error"]').text()).toContain('too large')
    expect(fetch).not.toHaveBeenCalled()
    await feed(new File([new Uint8Array(10)], 'ok.png', { type: 'image/png' }))
    const [url, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit]
    expect(url).toBe('/api/v1/me/avatar')
    expect(init.method).toBe('PUT')
    expect((init.headers as Record<string, string>)['X-CSRF-Token']).toBe('tok123')
    expect((init.headers as Record<string, string>)['Content-Type']).toBe('image/png')
    expect(w.findComponent(AvatarEditor).emitted('update:modelValue')![0]).toEqual(['/api/v1/users/u1/avatar/abc'])
    await w.setProps({ p: { modelValue: '/api/v1/users/u1/avatar/abc', name: 'Dana Kovač', uploadPath: '/api/v1/me/avatar', removePath: '/api/v1/me/avatar' } })
    await w.find('[data-test="avatar-remove"]').trigger('click')
    await flushPromises()
    expect(fetch).toHaveBeenLastCalledWith('/api/v1/me/avatar', expect.objectContaining({ method: 'DELETE' }))
    expect(w.findComponent(AvatarEditor).emitted('update:modelValue')![1]).toEqual([''])
  })

  it('announces a profile change to the platform shell after saving', async () => {
    stubFetch((url, init) => {
      if (url === '/api/v1/session') return { status: 200, body: { user: { id: 'u1', email: 'dana@x.test', display_name: 'Dana Kovač' }, tenant: { id: 't1' }, roles: [] } }
      if (url === '/api/v1/me/profile' && init?.method === 'PUT') return { status: 200, body: profile }
      return { status: 200, body: profile }
    })
    useSession().apply({ user: { id: 'u1', email: 'dana@x.test' }, tenant: { id: 't1' }, roles: [] })
    const heard = vi.fn()
    window.addEventListener(SESSION_CHANGED_EVENT, heard)
    const w = mountView(Account)
    await flushPromises()
    await w.find('[data-test="profile-form"] form').trigger('submit')
    await flushPromises()
    expect(heard).toHaveBeenCalled()
    window.removeEventListener(SESSION_CHANGED_EVENT, heard)
  })
})
