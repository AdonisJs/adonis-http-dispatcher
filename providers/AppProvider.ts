/*
* @adonisjs/core
*
* (c) Harminder Virk <virk@adonisjs.com>
*
* For the full copyright and license information, please view the LICENSE
* file that was distributed with this source code.
*/

import { IocContract } from '@adonisjs/fold'
import { ServerContract } from '@ioc:Adonis/Core/Server'
import { ConfigContract } from '@ioc:Adonis/Core/Config'
import { ApplicationContract } from '@ioc:Adonis/Core/Application'

import { HealthCheck } from '../src/HealthCheck'
import envChecker from '../src/HealthCheck/Checkers/Env'
import appKeyChecker from '../src/HealthCheck/Checkers/AppKey'
import { HttpExceptionHandler } from '../src/HttpExceptionHandler'
import { EnvContract } from '@ioc:Adonis/Core/Env'

/**
 * The application provider that sticks all core components
 * to the container.
 */
export default class AppProvider {
  constructor (protected container: IocContract) {
  }

  /**
   * Additional providers to load
   */
  public provides = [
    '@adonisjs/env',
    '@adonisjs/config',
    '@adonisjs/profiler',
    '@adonisjs/logger',
    '@adonisjs/encryption',
    '@adonisjs/events',
    '@adonisjs/hash',
    '@adonisjs/http-server',
    '@adonisjs/bodyparser',
    '@adonisjs/validator',
  ]

  /**
   * Register `HttpExceptionHandler` to the container.
   */
  protected registerHttpExceptionHandler () {
    this.container.bind('Adonis/Core/HttpExceptionHandler', () => HttpExceptionHandler)
  }

  /**
   * Registering the health check provider
   */
  protected registerHealthCheck () {
    this.container.singleton('Adonis/Core/HealthCheck', () => {
      return new HealthCheck(this.container.use('Adonis/Core/Application'))
    })
  }

  /**
   * Lazy initialize the cors hook, if enabled inside the config
   */
  protected registerCorsHook () {
    /**
     * Register the cors before hook with the server
     */
    this.container.with([
      'Adonis/Core/Config',
      'Adonis/Core/Server',
    ], (Config: ConfigContract, Server: ServerContract) => {
      const config = Config.get('cors', {})
      if (!config.enabled) {
        return
      }

      const Cors = require('../src/Hooks/Cors').Cors
      const cors = new Cors(config)
      Server.hooks.before(cors.handle.bind(cors))
    })
  }

  /**
   * Lazy initialize the static assets hook, if enabled inside the config
   */
  protected registerStaticAssetsHook () {
    /**
     * Register the cors before hook with the server
     */
    this.container.with([
      'Adonis/Core/Config',
      'Adonis/Core/Server',
      'Adonis/Core/Application',
    ], (Config: ConfigContract, Server: ServerContract, Application: ApplicationContract) => {
      const config = Config.get('static', {})
      if (!config.enabled) {
        return
      }

      const ServeStatic = require('../src/Hooks/Static').ServeStatic
      const serveStatic = new ServeStatic(Application.publicPath(), config)
      Server.hooks.before(serveStatic.handle.bind(serveStatic))
    })
  }

  /**
   * Registers base health checkers
   */
  protected registerHealthCheckers () {
    this.container.with(['Adonis/Core/Env', 'Adonis/Core/HealthCheck'],
      (env: EnvContract, healthCheck: HealthCheck) => {
        envChecker(healthCheck, env.get('NODE_ENV', undefined) as string | undefined)
        appKeyChecker(healthCheck, env.get('APP_KEY', undefined) as string | undefined)
      })
  }

  /**
   * Registering all required bindings to the container
   */
  public register () {
    this.registerHttpExceptionHandler()
    this.registerHealthCheck()
  }

  /**
   * Register hooks and health checkers on boot
   */
  public boot () {
    this.registerCorsHook()
    this.registerStaticAssetsHook()
    this.registerHealthCheckers()
  }
}
