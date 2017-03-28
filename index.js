const _ = require('lodash'),
  cookieParser = require('cookie-parser'),
  passport = require('passport'),
  session  = require('express-session');


const EVENT_FAIL  = 'passport:fail',
  EVENT_OK    = 'passport:ok';

function isFunction(functionToCheck) {
  const getType = {};
  return functionToCheck && getType.toString.call(functionToCheck) === '[object Function]';
}

const BrestPassport =
  {
    init: function(brest, callback){
      brest.getApp().use(cookieParser());
      const sessionSettings = brest.getSetting('passport', {
        secret: 'defaultpassportsecret',
        cookie: { maxAge:  2629743830},
        store: require('express-session/session/store'),
        adminRole: 'admin'
      });
      if (isFunction(sessionSettings.store)) {
        const SessionStore = sessionSettings.store(session);
        const sessionStoreSettings = sessionSettings.storeSettingsKey ? brest.getSetting(sessionSettings.storeSettingsKey) : null;
        sessionSettings.store = new SessionStore(sessionStoreSettings);
      }
      brest.getApp().use(session(sessionSettings));
      brest.getApp().use(passport.initialize());
      brest.getApp().use(passport.session());
      BrestPassport.brest = brest;
      BrestPassport.adminRole = sessionSettings.adminRole;
      callback();
    },

    method: {

        /**
         * Function is called after the express.js middleware and before the Brest handler.
         * callback(true) stands for failed authentication.
         * @param method
         * @param req
         * @param callback
         */
      authenticate: function(method, req, callback){
        let i;
        if (_.isEmpty(req.user)) {
          BrestPassport.brest.emit(EVENT_FAIL, req.user);
          return callback({denied: 'Authorisation failed'});
        } else {

          if (req.user.roles && req.user.roles.indexOf(BrestPassport.adminRole) > -1) {
            BrestPassport.brest.emit(EVENT_OK, req.user);
            return callback();
          }

          const methodFields = method.getFields();

          if (methodFields.roles) {
            if (req.user.roles) {
              let roleChecked = false;
              for (i = 0; i < req.user.roles.length; i++) {
                if (methodFields.roles.indexOf(req.user.roles[i]) > -1) {
                  roleChecked = true;
                  break;
                }
              }
              if (!roleChecked) {
                BrestPassport.brest.emit(EVENT_FAIL, req.user);
                return callback({denied: 'User has no role allowed for this method'});
              }
            }
          }

          if (methodFields.denyRoles) {
            for (i = 0; i < req.user.roles.length; i++) {
              if (methodFields.denyRoles.indexOf(req.user.roles[i]) > -1) {
                BrestPassport.brest.emit(EVENT_FAIL, req.user);
                return callback({denied: 'User has roles that are not allowed for this method'});
              }
            }
          }
          BrestPassport.brest.emit(EVENT_OK, req.user);
          return callback();
        }
      }
    }
  };

BrestPassport.passport = passport;

module.exports = BrestPassport;