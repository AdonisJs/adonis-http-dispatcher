'use strict'

/**
 * adonis-framework
 *
 * (c) Harminder Virk <virk@adonisjs.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
*/

const nunjucks = require('nunjucks')
const ViewLoader = require('./loader')
const viewFilters = require('./filters')
const viewExtensions = require('./extensions')

/**
 * View class for adonis framework to serve jinja like views
 * @class
 * @alias View
 */
class View {

  constructor (Helpers, Config, Route) {
    const viewsPath = Helpers.viewsPath()
    const viewsCache = Config.get('app.views.cache', true)
    this.viewsEnv = new nunjucks.Environment(new ViewLoader(viewsPath, false, !viewsCache))
    viewExtensions(this.viewsEnv)
    viewFilters(this.viewsEnv, Route)
  }

  /**
   * compile a view with give template and data
   *
   * @param  {String} templatePath
   * @param  {Object} [data]
   * @return {Promise}
   *
   * @example
   * View
   *   .make('index', {})
   *   .then()
   *   .catch()
   * @public
   */
  make (templatePath, data) {
    let self = this
    return new Promise(function (resolve, reject) {
      self.viewsEnv.render(templatePath, data, function (err, templateContent) {
        if (err) {
          reject(err)
          return
        }
        resolve(templateContent)
      })
    })
  }

  /**
   * makes a view from string instead of path, it is
   * helpful for making quick templates on the
   * fly.
   *
   * @param  {String}   templateString
   * @param  {Object}   [data]
   * @return {String}
   *
   * @example
   * view.makeString('Hello {{ user }}', {user: 'doe'})
   *
   * @public
   */
  makeString (templateString, data) {
    return this.viewsEnv.renderString(templateString, data)
  }

  /**
   * add a filter to view, it also support async execution
   *
   * @param  {String}   name
   * @param  {Function} callback
   * @param  {Boolean}   async
   *
   * @example
   * View.filter('name', function () {
   * }, true)
   *
   * @public
   */
  filter (name, callback, async) {
    this.viewsEnv.addFilter(name, callback, async)
  }

  /**
   * add a global method to views
   *
   * @param  {String} name
   * @param  {*} value
   *
   * @example
   * View.global('key', value)
   *
   * @public
   */
  global (name, value) {
    this.viewsEnv.addGlobal(name, value)
  }
}

module.exports = View
