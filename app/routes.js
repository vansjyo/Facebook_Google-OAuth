var User = require('./models/user');
var express= require('express');
var app= express();
module.exports = function(app, passport){

	app.get('/', function(req, res){
		res.render('index.ejs');
	});

	app.get('/signin', function(req, res){
		res.render('index.ejs', { message: req.flash('loginMessage') });
	});
	

	app.get('/home', isLoggedIn, function(req, res){
		console.log("hey its the user here");
		console.log(req.user);
		res.render('home.ejs', { user: req.user });
	});
 
	
    app.get('/auth/facebook', passport.authenticate('facebook',{ scope:['email']}));


    app.get('/auth/facebook/callback',
       passport.authenticate('facebook', { successRedirect: '/home',
                                      failureRedirect: '/' }));

    app.get('/auth/google', passport.authenticate('google',{ scope:['profile','email']}));


    app.get('/auth/google/callback',
       passport.authenticate('google', { successRedirect: '/home',
                                      failureRedirect: '/' }));


	app.get('/logout', function(req, res){
		req.logout();
		res.redirect('/');
	})
};

function isLoggedIn(req, res, next) {
	if(req.isAuthenticated()){
		return next();
	}

	res.redirect('/login');
}