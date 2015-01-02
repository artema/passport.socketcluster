var passport = require('passport'),
    xtend = require('xtend');

function parseCookie(options, header) {
  var cookieParser = options.cookieParser(options.secret),
  req = { headers: { cookie: header } };

  var cookie;
  cookieParser(req, {}, function(err) {
    if (err) {
      throw err;
    }
    cookie = req.signedCookies || req.cookies;
  });
  return cookie;
}

exports.handshake = function(options) {
  if (!options.cookieParser) {
    throw new Error('cookieParser is not provided.');
  }

  if (!options.store) {
    throw new Error('store is not provided.');
  }

  if (!options.secret) {
    throw new Error('secret is not provided.');
  }

  if (!options.callback) {
    throw new Error('callback is not provided.');
  }

  var defaultOptions = {
    passport:     passport,
    key:          'connect.sid'
  };

  options = xtend(defaultOptions, options);
  options.userProperty = options.passport._userProperty || 'user';

  return function(req, next) {
    var cookie = parseCookie(options, req.headers.cookie || ''),
        sessionID = cookie[options.key] || '';

    function success(user) {
      options.callback(null, req, user, next);
    }

    function failure(err) {
      options.callback(err, req, null, next);
    }

    options.store.get(sessionID, function(err, session) {
      if (err) {
        return failure('Session store error: ' + err.message);
      }

      if (!session) {
        return failure('No session found.');
      }

      var sessionKey = options.passport._key;

      if (!session[sessionKey]) {
        return failure('Passport was not initialized.');
      }

      var userKey = session[sessionKey][options.userProperty];

      if (!userKey) {
        return failure('User not authorized through passport.');
      }

      options.passport.deserializeUser(userKey, function(err, user) {
        if (err) {
          return failure(err);
        }

        if (!user) {
          return failure('User not found.');
        }

        user.logged_in = true;
        success(user);
      });
    });
  };
};
