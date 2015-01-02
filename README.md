# SocketCluster Passport.js authentication middleware

A [SocketCluster](http://socketcluster.io/) middleware for authenticating socket connections with [Passport.js](http://passportjs.org/).

## Install

    npm install passport.socketcluster

## Usage

    //worker.js
    
    var session = require('express-session'),
        express = require('express'),
        cookieParser = require('cookie-parser'),
        passport = require('passport'),
        passportSocketCluster = require('passport.socketcluster'),
        RedisStore = require('connect-redis')(session);
    
    module.exports.run = function(worker) {
      var app = express(),
          store = new RedisStore(),
          cookieKey = 'session',
          cookieSecret = 'keyboard cat';
  
      var server = worker.getHTTPServer(),
          sc = worker.getSCServer();

      server.on('req', app);
  
      app.use(session({
        name:     cookieKey,
        secret:   cookieSecret,
        store:    store
      }));
  
      app.use(passport.initialize());
      app.use(passport.session());
      
      //Handshake authentication
      sc.addMiddleware(sc.MIDDLEWARE_HANDSHAKE, passportSocketCluster.handshake({
        cookieParser:cookieParser,
        key:         cookieKey,
        secret:      cookieSecret,
        store:       store,
        passport:    passport,
        callback:    function(err, req, user, next) {
          if (err) {
            return next(err);
          }
          //Save Passport user for later use
          req.session.set('user', user, next);
        }
      }));
    };
