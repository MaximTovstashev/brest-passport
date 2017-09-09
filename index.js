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
    name: 'brest-passport',
    before_api_init: function(brest, callback){
      brest.app.use(cookieParser());
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
      brest.app.use(session(sessionSettings));
      brest.app.use(passport.initialize());
      brest.app.use(passport.session());
      BrestPassport.brest = brest;
      BrestPassport.adminRole = sessionSettings.adminRole;
      callback();
    },

    // init: (brest, callback) => {
    //   console.log('PASSPORT INIT');
    //   callback();
    // },

    endpoint: {

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

          let roles = req.user.roles || req.user.role ? [req.user.role] : [];


          if (roles.indexOf(BrestPassport.adminRole) > -1) {
            BrestPassport.brest.emit(EVENT_OK, req.user);
            return callback();
          }

          const methodFields = method.getFields();

          if (methodFields.roles) {
            if (roles.length) {
              let roleChecked = false;
              for (i = 0; i < roles.length; i++) {
                if (methodFields.roles.indexOf(roles[i]) > -1) {
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
            for (i = 0; i < roles.length; i++) {
              if (methodFields.denyRoles.indexOf(roles[i]) > -1) {
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