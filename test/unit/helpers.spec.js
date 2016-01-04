'use strict'

/**
 * adonis-framework
 * Copyright(c) 2015-2015 Harminder Virk
 * MIT Licensed
*/

const Helpers = require('../../src/Helpers')
const chai = require('chai')
const path = require('path')
const expect = chai.expect

const basePath = path.join(__dirname,'../acceptance');

describe("Helpers", function () {

  it('should throw error when autoload does exists in package file', function () {
    const fn = function () {
      Helpers.load(path.join(__dirname,'./package.test.json'))
    }
    expect(fn).to.throw(/autoload must be enable/)
  })

  it('should throw error when autoload exists but not configured', function () {
    const fn = function () {
      Helpers.load(path.join(__dirname,'./package.another.json'))
    }
    expect(fn).to.throw(/autoload must be enable/)
  })

  it('should set autoload values when Ioc instance is passed to load method', function () {
    let appKey, appNamesapce
    const Ioc = {
      autoload: function (namespace, key) {
        appKey = key
        appNamesapce = namespace
      }
    }
    Helpers.load(path.join(basePath,'./package.test.json'), Ioc)
    expect(appKey).to.equal(path.join(basePath, './app'))
    expect(appNamesapce).to.equal('App')
  })

  context('After Load', function () {
    before(function () {
      Helpers.load(path.join(basePath,'./package.test.json'))
    })
    it('should return project base directory path', function () {
      expect(Helpers.basePath()).to.equal(basePath)
    })

    it('should return project app directory path', function () {
      expect(Helpers.appPath()).to.equal(path.join(basePath,'./app'))
    })

    it('should return project public directory path', function () {
      expect(Helpers.publicPath()).to.equal(path.join(basePath,'./public'))
    })

    it('should return public path to a given file', function () {
      expect(Helpers.publicPath('style.css')).to.equal(path.join(basePath,'./public/style.css'))
    })

    it('should return project config directory path', function () {
      expect(Helpers.configPath()).to.equal(path.join(basePath,'./config'))
    })

    it('should return config path to a given file', function () {
      expect(Helpers.configPath('database.js')).to.equal(path.join(basePath,'./config/database.js'))
    })

    it('should return project storage directory path', function () {
      expect(Helpers.storagePath()).to.equal(path.join(basePath,'./storage'))
    })

    it('should return storage path to a given file', function () {
      expect(Helpers.storagePath('cache')).to.equal(path.join(basePath,'./storage/cache'))
    })

    it('should return project resources directory path', function () {
      expect(Helpers.resourcesPath()).to.equal(path.join(basePath,'./resources'))
    })

    it('should return resources path to a given file', function () {
      expect(Helpers.resourcesPath('views')).to.equal(path.join(basePath,'./resources/views'))
    })

    it('should return project migrations directory path', function () {
      expect(Helpers.migrationsPath()).to.equal(path.join(basePath,'./migrations'))
    })

    it('should return migrations path to a given file', function () {
      expect(Helpers.migrationsPath('1234.js')).to.equal(path.join(basePath,'./migrations/1234.js'))
    })

    it('should return project views directory path', function () {
      expect(Helpers.viewsPath()).to.equal(path.join(basePath,'./resources/views'))
    })

    it('should encode base64 string', function () {
      expect(Helpers.base64Encode('Romain Lanz')).to.equal('Um9tYWluIExhbno=')
    })

    it('should decode base64 string', function () {
      expect(Helpers.base64Decode('Um9tYWluIExhbno=')).to.equal('Romain Lanz')
    })
  })


})
