/*
 * @adonisjs/core
 *
 * (c) Harminder Virk <virk@adonisjs.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import test from 'japa'
import { Ioc } from '@adonisjs/fold'
import { Application } from '@adonisjs/application/build/standalone'

import { HealthCheck } from '../src/HealthCheck'
import appKeyHealthChecker from '../src/HealthCheck/Checkers/AppKey'

test.group('Env Health Checker', () => {
  test('fail when APP_KEY is not defined', async (assert) => {
    const application = new Application(__dirname, new Ioc(), {}, {})
    const healthCheck = new HealthCheck(application)
    appKeyHealthChecker(healthCheck)

    const report = await healthCheck.getReport()
    assert.deepEqual(report.report, {
      appKey: {
        displayName: 'App Key Check',
        health: {
          healthy: false,
          message: 'Missing APP_KEY environment variable. It is required to keep your application secure',
        },
      },
    })
  })

  test('fail when APP_KEY is not secure', async (assert) => {
    const application = new Application(__dirname, new Ioc(), {}, {})
    const healthCheck = new HealthCheck(application)
    appKeyHealthChecker(healthCheck, '3910200')

    const report = await healthCheck.getReport()
    assert.deepEqual(report.report, {
      appKey: {
        displayName: 'App Key Check',
        health: {
          healthy: false,
          // eslint-disable-next-line max-len
          message: 'Insecure APP_KEY. It must be 32 characters long. Run \"node ace generate:key\" to generate a secure key',
        },
      },
    })
  })

  test('work fine when APP_KEY is secure', async (assert) => {
    const application = new Application(__dirname, new Ioc(), {}, {})
    const healthCheck = new HealthCheck(application)
    appKeyHealthChecker(healthCheck, 'asecureandlongrandomsecret')

    const report = await healthCheck.getReport()
    assert.deepEqual(report.report, {
      appKey: {
        displayName: 'App Key Check',
        health: {
          healthy: false,
          // eslint-disable-next-line max-len
          message: 'Insecure APP_KEY. It must be 32 characters long. Run \"node ace generate:key\" to generate a secure key',
        },
      },
    })
  })
})
