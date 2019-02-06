<?php 

namespace Jonathan\Model;
use \Jonathan\DB\Sql;
use \Jonathan\Model;

class User extends Model {

	const SESSION = "User";

	public static function login($login, $password){

		$sql = new Sql();
		$results = $sql->select("SELECT * FROM tb_users WHERE deslogin = :LOGIN", array(":LOGIN" => $login));

		if(count($results) === 0)
		{
			throw new Exception("Usuário ou Senha Inválidos");			
		} else {

			$data = $results[0];

			if(password_verify($password, $data["despassword"]))
			{

				$user = new User();

				$user->setData($data);

				$_SESSION[User::SESSION] = $user->getValues();

				header("Location: /admin");

				exit;

			} else {

				throw new \Exception("Usuário ou Senha Inválidos");

			}

		}

	}

	public static function verify_login($inadmin = true){

		if(
			!isset($_SESSION[User::SESSION]) 
			|| !($_SESSION[User::SESSION])
			|| !(int)$_SESSION[User::SESSION]["iduser"] > 0
			|| (bool)$_SESSION[User::SESSION]["inadmin"] !== $inadmin
		)
		{
			header("Location: /admin/login");
			exit;
		} else {
			header("Location: /admin");
		}

	}

	public static function logout(){

		$_SESSION[User::SESSION] = NULL;

	}

}

 ?>