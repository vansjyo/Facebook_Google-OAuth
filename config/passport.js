var LocalStrategy = require('passport-local').Strategy;
var FacebookStrategy = require('passport-facebook').Strategy;
var GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;
var passport= require('passport');
var User = require('../app/models/user');

module.exports = function(passport) {


	passport.serializeUser(function(user, done){
		done(null, user.id);
	});

	passport.deserializeUser(function(id, done){
		User.findById(id, function(err, user){
			done(err, user);
		});
	});


	passport.use('local-signup', new LocalStrategy({
		usernameField: 'email',
		passwordField: 'password',
		passReqToCallback: true
	},
	function(req, email, password, done){
		process.nextTick(function(){
			User.findOne({'local.username': email}, function(err,user){
				if(err)
					return done(err);
				if(user){
					return done(null, false, req.flash('signupMessage', 'That email already taken'));
				} else {
					var newUser = new User();
					newUser.local.username = email;
					newUser.local.password = newUser.generateHash(password);

					newUser.save(function(err){
						if(err)
							throw err;
						return done(null, newUser);
					})
				}
			})

		});
	}));

	passport.use('local-login', new LocalStrategy({
		usernameField: 'email',
		passwordField: 'password',
		passReqToCallback: true
	},
	function(req, email, password, done){
		process.nextTick(function(){
			User.findOne({ 'local.username': email}, function(err, user){
				if(err)
					return done(err);
				if(!user)
					return done(null, false, req.flash('loginMessage', 'No User found'));
				if(!user.validPassword(password))
					return done(null, false, req.flash('loginMessage', 'invalid password'));

				return done(null, user);

			});
		});
	}
	));


	

	passport.use(new FacebookStrategy({
		clientID: '***********',
		enableProof:true,
		clientSecret: '*************************************', 
		callbackURL: 'http://localhost:8080/auth/facebook/callback',
		profileFields: ['id', 'name','photos', 'displayName'], 

	},
	function(accessToken, refreshToken, profile, done) {
		console.log(profile);
		process.nextTick(function(){
			User.findOne({'facebook.id' : profile.id, picture: profile.photos ? profile.photos[0].value : '/img/faces/unknown-user-pic.jpg'}, function(err,user){
				if (err)
					return done(err);
				if(user)
					return done(null,user);
				else{
					var newUser = new User();
					newUser.facebook.id = profile.id;
					newUser.facebook.token= accessToken;
					newUser.facebook.name = profile.displayName;

					newUser.save(function(err){
						if(err)
							throw err;
						return done(null,newUser);
					})
					console.log(profile);
				}
			});
		});
	}
	));


	passport.use(new GoogleStrategy({
		clientID: '************************************************',
		enableProof:true,
		clientSecret: '***************************', 
		callbackURL: 'http://localhost:8080/auth/google/callback',
	 

	},
	function(accessToken, refreshToken, profile, done) {
		console.log(profile);
		process.nextTick(function(){
			User.findOne({'google.id' : profile.id, picture: profile.photos ? profile.photos[0].value : '/img/faces/unknown-user-pic.jpg'}, function(err,user){
				if (err)
					return done(err);
				if(user)
					return done(null,user);
				else{
					var newUser = new User();
					newUser.google.id = profile.id;
					newUser.google.token= accessToken;
					newUser.google.name = profile.displayName;
					newUser.google.photo = profile.photos[0].value;

					newUser.save(function(err){
						if(err)
							throw err;
						return done(null,newUser);
					})
					console.log(profile);
				}
			});
		});
	}
	));


};



