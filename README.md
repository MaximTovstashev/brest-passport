#Brest-passport

[Passport.js](http://passportjs.org/) authentication wrapper for [Brest](https://github.com/MaximTovstashev/brest) library.

##Installation

In your project root run

`$ npm install brest-passport --save`

to install the latest version and save it to your `package.json` file.

##Setup

Upon Brest initialization, require `brest-passport` and add it to the plugins initialization inside `brest.ready` event callback.
Use `BrestPassport.passport` to initialize authentication strategies.
 
In this example we use passport local strategy initialization from passport.js official guide.

```javascript
const BrestPassport = require('brest-passport'),
	  LocalStrategy = require('passport-local').Strategy;

//...

brest.on('ready', function(){

	brest.use(
	  [   BrestPassport ]);
	
	const passport = BrestPassport.passport;
	
	passport.use(new LocalStrategy(
	  function(username, password, done) {
		User.findOne({ username: username }, function(err, user) {
		  if (err) { return done(err); }
		  if (!user) {
			return done(null, false, { message: 'Incorrect username.' });
		  }
		  if (!user.validPassword(password)) {
			return done(null, false, { message: 'Incorrect password.' });
		  }
		  return done(null, user);
		});
	  }
	));

});
```

## Changes

### 0.1.1
- Can use `user.role` for a single role check



