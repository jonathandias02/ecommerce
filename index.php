<?php 

session_start();

require_once("vendor/autoload.php");

use Jonathan\Page;
use Jonathan\PageAdmin;
use Jonathan\Model\User;

$app = new \Slim\Slim();

$app->config('debug', true);

$app->get('/', function() {
    
	$page = new Page();

	$page->setTpl("index");

});

$app->get('/admin', function() {

	User::verify_login();
    
	$page = new PageAdmin();

	$page->setTpl("index");

});

$app->get("/admin/login", function(){


	$page = new PageAdmin(["header" => false, "footer" => false]);

	$page->setTpl("login");

});

$app->post("/admin/login", function(){

	User::login($_POST["login"], $_POST["password"]);

	header("Location: admin/");
	exit;

});

$app->get('/admin/logout', function() {

	User::logout();
	header("Location: /admin");
	exit;

});

$app->run();

 ?>