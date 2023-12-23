/*
 * @adonisjs/core
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { test } from '@japa/runner'
import { AceFactory } from '../../factories/core/ace.js'
import MakeProvider from '../../commands/make/provider.js'
import { StubsFactory } from '../../factories/stubs.js'

test.group('Make provider', () => {
  test('create provider class', async ({ assert, fs }) => {
    await fs.createJson('tsconfig.json', {})
    await fs.create('adonisrc.ts', `export default defineConfig({})`)

    const ace = await new AceFactory().make(fs.baseUrl, {
      importer: (filePath) => import(filePath),
    })
    await ace.app.init()
    ace.ui.switchMode('raw')

    const command = await ace.create(MakeProvider, ['app'])
    await command.exec()

    const { contents } = await new StubsFactory().prepare('make/provider/main.stub', {
      entity: ace.app.generators.createEntity('app'),
    })

    await assert.fileEquals('providers/app_provider.ts', contents)

    assert.deepEqual(ace.ui.logger.getLogs(), [
      {
        message: 'green(DONE:)    create providers/app_provider.ts',
        stream: 'stdout',
      },
      {
        message: 'green(DONE:)    update adonisrc.ts file',
        stream: 'stdout',
      },
    ])

    await assert.fileContains('adonisrc.ts', `() => import('./providers/app_provider.js')`)
  })

  test('create provider class for a specific environment', async ({ assert, fs }) => {
    await fs.createJson('tsconfig.json', {})
    await fs.create('adonisrc.ts', `export default defineConfig({})`)

    const ace = await new AceFactory().make(fs.baseUrl, {
      importer: (filePath) => import(filePath),
    })
    await ace.app.init()
    ace.ui.switchMode('raw')

    const command = await ace.create(MakeProvider, ['app', '-e=web', '-e=repl'])
    await command.exec()

    const { contents } = await new StubsFactory().prepare('make/provider/main.stub', {
      entity: ace.app.generators.createEntity('app'),
    })

    assert.deepEqual(ace.ui.logger.getLogs(), [
      {
        message: 'green(DONE:)    create providers/app_provider.ts',
        stream: 'stdout',
      },
      {
        message: 'green(DONE:)    update adonisrc.ts file',
        stream: 'stdout',
      },
    ])

    await assert.fileEquals('providers/app_provider.ts', contents)
    await assert.fileContains('adonisrc.ts', [
      `() => import('./providers/app_provider.js')`,
      `environment: ['web', 'repl']`,
    ])
  })

  test('show error when selected environment is invalid', async ({ assert, fs }) => {
    await fs.createJson('tsconfig.json', {})
    await fs.create('adonisrc.ts', `export default defineConfig({})`)

    const ace = await new AceFactory().make(fs.baseUrl, {
      importer: (filePath) => import(filePath),
    })
    await ace.app.init()
    ace.ui.switchMode('raw')

    const command = await ace.create(MakeProvider, ['app', '--environments=foo'])
    await command.exec()

    assert.deepEqual(ace.ui.logger.getLogs(), [
      {
        message:
          '[ red(error) ] Invalid environment(s) "foo". Only "web,console,test,repl" are allowed',
        stream: 'stderr',
      },
    ])
  })
})
