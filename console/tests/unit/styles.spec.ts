// The kit's UiCheckbox/UiSwitch rely on a flex `label.label` that FlyonUI 2
// does not provide; kit-fixes.css restores it in both builds.
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

const read = (name: string) => readFileSync(resolve(__dirname, '../../src', name), 'utf8')

describe('console stylesheets', () => {
  it('lay kit checkbox labels out on one centred line in the standalone and remote builds', () => {
    expect(read('app.css')).toContain('@import "./kit-fixes.css";')
    expect(read('remote.css')).toContain('@import "./kit-fixes.css";')
    expect(read('kit-fixes.css')).toMatch(/\.form-control > label\.label \{\s*display: flex;\s*align-items: center;/)
  })
})
