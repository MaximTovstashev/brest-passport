var cookieParser = require('cookie-parser');
var passport = require('passport');
var session  = require('express-session');

function isFunction(functionToCheck) {
    var getType = {};
    return functionToCheck && getType.toString.call(functionToCheck) === '[object Function]';
}

var BrestPassport =
{
    init: function(brest){
        brest.getApp().use(cookieParser());
        var SessionStore = brest.getSetting('passport.store');
        var sessionSettings = {
            secret: brest.getSetting('passport.secret','defaultpassportsecret'),
            cookie: { maxAge:  brest.getSetting('passport.maxAge', 2629743830)}
        };
        if (isFunction(SessionStore)) sessionSettings.store = new SessionStore();
        brest.getApp().use(session(sessionSettings));
        brest.getApp().use(passport.initialize());
        brest.getApp().use(passport.session());
    },

    method: {

        authenticate: function(method, req, callback){
            if (req.user) {

                if (req.user.roles && req.user.roles.indexOf('admin') > -1) {
                    callback();
                    return;
                }

                if (method.description.roles) {
                    if (req.user.roles) {
                            var roleChecked = false;
                            for (var i=0; i<req.user.roles.length; i++){
                                if (method.description.roles.indexOf(req.user.roles[i]) > -1) {
                                    roleChecked = true;
                                    break;
                                }
                            }
                            if (!roleChecked) {
                                callback({roles: 'failed'});
                                return;
                            }
                        }
                    }

                if (method.description.denyRoles) {
                    for (var i=0; i<req.user.roles.length; i++){
                        if (method.description.denyRoles.indexOf(req.user.roles[i]) > -1) {
                            callback({denyRoles: 'failed'});
                            return;
                        }
                    }
                }

                callback();
            }
            else callback(true);
        }
    }
};

BrestPassport.store = require('express-session/session/store');
BrestPassport.passport = passport;

module.exports = BrestPassport;