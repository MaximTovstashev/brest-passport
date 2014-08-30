var passport = require('passport');
var session  = require('express-session');

var BrestPassport =
{
    init: function(brest){
        brest.getApp().use(session({ secret: brest.getSetting('passport.secret','defaultpassportsecret')}));
        brest.getApp().use(passport.initialize());
        brest.getApp().use(passport.session());
        brest.getPassport = function(){return passport};
    },

    method: {
        authenticate: function(method, req, callback){
            if (req.user) callback();
            else callback(true);
        },

        beforeHandler: function(method, req, callback){
            if (method.description.passportStrategy){
                passport.authenticate(method.description.passportStrategy);
            }
            if (method.description.passportStrategyReturn) {
                passport.authenticate(method.description.passportStrategyReturn,
                    { successRedirect: brest.getSetting('passport.successRedirect','/'),
                      failureRedirect: brest.getSetting('passport.failureRedirect','/login') });
            }
            if (method.description.passportLogout){
                req.logout();
            }
            callback();
        }
    }
};