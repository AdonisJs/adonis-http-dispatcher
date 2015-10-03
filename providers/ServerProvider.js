'use strict'

/**
 * adonis-framework
 * Copyright(c) 2015-2015 Harminder Virk
 * MIT Licensed
*/

const ServiceProvider = require('adonis-fold').ServiceProvider

class ServerProvider extends ServiceProvider {

  /**
   * @function inject
   * @description Defining injections
   * @return {Array}
  */
  static get inject(){
    return ["Adonis/Src/Route","Adonis/Src/Request","Adonis/Src/Response","Adonis/Src/Logger","Adonis/Src/Session"]
  }

  /**
   * @function register
   * @description Binding Server to ioc container
  */
  * register () {
    this.app.bind('Adonis/Src/Server', function (Route, Request, Response, Logger, Session) {
      const Server = require('../src/Server')
      return new Server(Route, Request, Response, Logger, Session)
    })
  }
}

module.exports = ServerProvider
