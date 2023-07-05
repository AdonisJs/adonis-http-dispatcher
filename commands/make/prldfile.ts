/*
 * @adonisjs/core
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import BaseCommand from './_base.js'
import { args, flags } from '../../modules/ace/main.js'
import { AppEnvironments } from '@adonisjs/application/types'

const ALLOWED_ENVIRONMENTS: AppEnvironments[] = ['web', 'console', 'test', 'repl']

/**
 * Make a new preload file
 */
export default class MakePreloadFile extends BaseCommand {
  static commandName = 'make:prldfile'
  static description = 'Create a new preload file inside the start directory'

  @args.string({ description: 'Name of the preload file' })
  declare name: string

  @flags.array({
    description: `Define the preload file environment. Accepted values "${ALLOWED_ENVIRONMENTS}"`,
  })
  declare environments: AppEnvironments[]

  /**
   * The stub to use for generating the preload file
   */
  protected stubPath: string = 'make/preload_file/main.stub'

  /**
   * Check if the mentioned environments are valid
   */
  #isValidEnvironment(environment: string[]): environment is AppEnvironments[] {
    return !environment.find((one) => !ALLOWED_ENVIRONMENTS.includes(one as any))
  }

  /**
   * Validate the environments flag passed by the user
   */
  #isEnvironmentsFlagValid() {
    if (!this.environments || !this.environments.length) {
      return true
    }

    return this.#isValidEnvironment(this.environments)
  }

  /**
   * Prompt for the environments
   */
  async #promptForEnvironments(): Promise<AppEnvironments[]> {
    const selectedEnvironments = await this.prompt.multiple(
      'Select the environment(s) in which you want to load this file',
      [
        { name: 'all', message: 'Load file in all environments' },
        { name: 'console', message: 'Environment for ace commands' },
        { name: 'repl', message: 'Environment for the REPL session' },
        { name: 'web', message: 'Environment for HTTP requests' },
        { name: 'test', message: 'Environment for the test process' },
      ] as const
    )

    if (selectedEnvironments.includes('all')) {
      return ['web', 'console', 'test', 'repl']
    }

    return selectedEnvironments as AppEnvironments[]
  }

  /**
   * Run command
   */
  async run() {
    let environments: AppEnvironments[] = this.environments

    /**
     * Ensure the environments are valid when provided via flag
     */
    if (!this.#isEnvironmentsFlagValid()) {
      this.logger.error(
        `Invalid environment(s) "${this.environments}". Only "${ALLOWED_ENVIRONMENTS}" are allowed`
      )
      return
    }

    /**
     * Prompt for the environments when not defined
     */
    if (!environments) {
      environments = await this.#promptForEnvironments()
    }

    const output = await this.generate(this.stubPath, {
      entity: this.app.generators.createEntity(this.name),
    })

    /**
     * Registering the preload file with the `.adonisrc.json` file. We register
     * the relative path, since we cannot be sure about aliases to exist.
     */
    const preloadImportPath = `./${output.relativeFileName.replace(/(\.js|\.ts)$/, '')}.js`
    await this.app.rcFileEditor
      .addPreloadFile(preloadImportPath, environments as Exclude<AppEnvironments, 'unknown'>[])
      .save()
  }
}
