/*
 * @adonisjs/core
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { test } from '@japa/runner'
import { StubsFactory } from '../../factories/stubs.js'
import { AceFactory } from '../../factories/core/ace.js'
import MakePreload from '../../commands/make/preload.js'

test.group('Make preload file', () => {
  test('create a preload file for all environments', async ({ assert, fs }) => {
    await fs.createJson('tsconfig.json', {})
    await fs.create('adonisrc.ts', `export default defineConfig({})`)

    const ace = await new AceFactory().make(fs.baseUrl, {
      importer: (filePath) => import(filePath),
    })
    await ace.app.init()
    ace.ui.switchMode('raw')

    const command = await ace.create(MakePreload, ['app'])
    await command.exec()

    const { contents } = await new StubsFactory().prepare('make/preload/main.stub', {
      entity: ace.app.generators.createEntity('app'),
    })
    await assert.fileEquals('start/app.ts', contents)
    console.log(ace.ui.logger.getLogs())

    assert.deepEqual(ace.ui.logger.getLogs(), [
      {
        message: 'green(DONE:)    create start/app.ts',
        stream: 'stdout',
      },
      {
        message: 'green(DONE:)    update adonisrc.ts file',
        stream: 'stdout',
      },
    ])

    await assert.fileContains('adonisrc.ts', `() => import('./start/app.js')`)
  })

  test('use environment flag to make preload file in a specific env', async ({ assert, fs }) => {
    await fs.createJson('tsconfig.json', {})
    await fs.create('adonisrc.ts', `export default defineConfig({})`)

    const ace = await new AceFactory().make(fs.baseUrl, {
      importer: (filePath) => import(filePath),
    })
    await ace.app.init()
    ace.ui.switchMode('raw')

    const command = await ace.create(MakePreload, [
      'app',
      '--environments=web',
      '--environments=repl',
    ])
    await command.exec()

    await assert.fileContains('adonisrc.ts', [
      `() => import('./start/app.js')`,
      `environment: ['web', 'repl']`,
    ])
  })

  test('display error when defined environment is not allowed', async ({ fs }) => {
    await fs.createJson('tsconfig.json', {})
    await fs.create('adonisrc.ts', `export default defineConfig({})`)

    const ace = await new AceFactory().make(fs.baseUrl, {
      importer: (filePath) => import(filePath),
    })
    await ace.app.init()
    ace.ui.switchMode('raw')

    const command = await ace.create(MakePreload, ['app'])
    command.environments = ['foo' as any]
    await command.exec()

    command.assertLog(
      '[ red(error) ] Invalid environment(s) "foo". Only "web,console,test,repl" are allowed'
    )
  })
})
