'use strict'

/*
 * adonis-framework
 *
 * (c) Harminder Virk <virk@adonisjs.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
*/

module.exports = function (View, Route, Config) {
  /**
   * Return url for the route
   */
  View.global('route', function (...args) {
    const url = Route.url(...args)
    const baseUrl = Config ? Config.get('app.http.baseUrl', '') : ''
    return url && /^http(s)?/.test(url) ? url : `${baseUrl}${url}`
  })

  /**
   * Make url for the assets file
   */
  View.global('assetsUrl', function (url) {
    const baseUrl = Config ? Config.get('app.http.baseUrl', '') : ''
    return url && /^\/|^http(s)?/.test(url) ? url : `${baseUrl}/${url}`
  })

  /**
   * Make link tag for css
   */
  View.global('css', function (url, skipPrefix = false) {
    url = !url.endsWith('.css') && !skipPrefix ? `${url}.css` : url
    return this.safe(`<link rel="stylesheet" href="${this.$globals.assetsUrl(url)}" />`)
  })

  /**
   * Make script tag for javascript
   */
  View.global('script', function (url, skipPrefix = false) {
    url = !url.endsWith('.js') && !skipPrefix ? `${url}.js` : url
    return this.safe(`<script type="text/javascript" src="${this.$globals.assetsUrl(url)}"></script>`)
  })
}
