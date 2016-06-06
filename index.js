var _ = require('lodash'),
    cookieParser = require('cookie-parser'),
    passport = require('passport'),
    session  = require('express-session'),
    util = require('util');

function isFunction(functionToCheck) {
    var getType = {};
    return functionToCheck && getType.toString.call(functionToCheck) === '[object Function]';
}

var BrestPassport =
{
    init: function(brest, callback){
        brest.getApp().use(cookieParser());
        var sessionSettings = brest.getSetting('passport', {
            secret: 'defaultpassportsecret',
            cookie: { maxAge:  2629743830},
            store: require('express-session/session/store')
        });
        if (isFunction(sessionSettings.store)) {
            var SessionStore = sessionSettings.store(session);
            var sessionStoreSettings = sessionSettings.storeSettingsKey ? brest.getSetting(sessionSettings.storeSettingsKey) : null;
            sessionSettings.store = new SessionStore(sessionStoreSettings);
        }
        brest.getApp().use(session(sessionSettings));
        brest.getApp().use(passport.initialize());
        brest.getApp().use(passport.session());
        BrestPassport.brest = brest;
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
            var i;
            if (_.isEmpty(req.user)) {
                BrestPassport.brest.emit('passport:fail', req.user);
                return callback({denied: "Authorisation failed"});
            } else {

                if (req.user.roles && req.user.roles.indexOf('admin') > -1) {
                    BrestPassport.brest.emit('passport:ok', req.user);
                    return callback();
                }

                var methodFields = method.getFields();

                if (methodFields.roles) {
                    if (req.user.roles) {
                        var roleChecked = false;
                        for (i = 0; i < req.user.roles.length; i++) {
                            if (methodFields.roles.indexOf(req.user.roles[i]) > -1) {
                                roleChecked = true;
                                break;
                            }
                        }
                        if (!roleChecked) {
                            BrestPassport.brest.emit('passport:fail', req.user);
                            return callback({denied: "User has no role allowed for this method"});
                        }
                    }
                }

                if (methodFields.denyRoles) {
                    for (i = 0; i < req.user.roles.length; i++) {
                        if (methodFields.denyRoles.indexOf(req.user.roles[i]) > -1) {
                            BrestPassport.brest.emit('passport:fail', req.user);
                            return callback({denied: "User has some roles that are not allowed for this method"});
                        }
                    }
                }
                BrestPassport.brest.emit('passport:ok', req.user);
                return callback();
            }
        }
    }
};

BrestPassport.passport = passport;

module.exports = BrestPassport;