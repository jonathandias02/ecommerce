<?php 

namespace Jonathan\Model;
use \Jonathan\DB\Sql;
use \Jonathan\Model;
use \Jonathan\Mailer;

class User extends Model {

	const SESSION = "User";
	const SECRET = "Jonathan_Secrets";
	const SECRET_IV = "Jonathan_Secrets";

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

	public static function logout()
	{

		$_SESSION[User::SESSION] = NULL;

	}

	public static function listUsers()
	{
		$sql = new Sql();

		return $sql->select("SELECT * FROM tb_users a INNER JOIN tb_persons b USING(idperson) ORDER BY b.desperson");

	}

	public function save()
	{

		$sql = new Sql();

		$results = $sql->select("CALL sp_users_save(:desperson, :deslogin, :despassword, :desemail, :nrphone, :inadmin)", array(
			":desperson"=>$this->getdesperson(),
			":deslogin"=>$this->getdeslogin(),
			":despassword"=>$this->getdespassword(),
			":desemail"=>$this->getdesemail(),
			":nrphone"=>$this->getnrphone(),
			":inadmin"=>$this->getinadmin()
		));

		$this->setData($results[0]);

	}

	public function get($id)
	{

		$sql = new Sql();

		$results = $sql->select("SELECT * FROM tb_users a INNER JOIN tb_persons b USING(idperson) WHERE a.iduser = :ID", array(

			":ID" => $id

		));

		$this->setData($results[0]);

	}

	public function update()
	{

		$sql = new Sql();

		$results = $sql->select("CALL sp_usersupdate_save(:iduser, :desperson, :deslogin, :despassword, :desemail, :nrphone, :inadmin)", array(
			":iduser"=>$this->getiduser(),
			":desperson"=>$this->getdesperson(),
			":deslogin"=>$this->getdeslogin(),
			":despassword"=>$this->getdespassword(),
			":desemail"=>$this->getdesemail(),
			":nrphone"=>$this->getnrphone(),
			":inadmin"=>$this->getinadmin()
		));

		$this->setData($results[0]);

	}

	public function delete(){

		$sql = new Sql();

		$sql->query("CALL sp_users_delete(:iduser)", array(

			":iduser" => $this->getiduser()

		));

	}

	public static function getForgot($email){

		$sql = new Sql();

		$results = $sql->select("SELECT * FROM tb_persons a INNER JOIN tb_users b USING(idperson)
			WHERE a.desemail = :email", array(":email" => $email));

		if(count($results) === 0)
		{

			throw new \Exception("Não foi possível recuperar senha.");
			
		}else
		{

			$data = $results[0];

			$results2 = $sql->select("CALL sp_userspasswordsrecoveries_create(:iduser, :desip)", array(

				":iduser" => $data["iduser"],
				":desip" => $_SERVER["REMOTE_ADDR"]

			));

			if(count($results2) === 0){

				throw new \Exception("Não foi possível recuperar senha.");				

			}else{

				$datarecovery = $results2[0];

				$code = base64_encode(openssl_encrypt($datarecovery["idrecovery"], 'AES-128-CBC', 
						User::SECRET, 0, User::SECRET_IV));

				$link = "http://www.hcodecommerce.com.br/admin/forgot/reset?code=$code";

				$mailer = new Mailer($data["desemail"], $data["desperson"], "Redefina sua senha do ecommerce!",
				"forgot", array("name"=>$data['desperson'],"link"=>$link));

				$mailer->send();

				return $data;

			}

		}

	}

	public static function validForgotDecrypt($code)
	{

		$idrecovery = openssl_decrypt(base64_decode($code), 'AES-128-CBC', User::SECRET, 0, User::SECRET_IV);

		$sql = new Sql;

		$results = $sql->select("

			SELECT * FROM tb_userspasswordsrecoveries a
			INNER JOIN tb_users b USING(iduser)
			INNER JOIN tb_persons c USING(idperson)
			WHERE
				a.idrecovery = :idrecovery
				AND
				a.dtrecovery IS NULL
				AND
				DATE_ADD(a.dtregister, INTERVAL 1 HOUR) >= NOW();

		", array(":idrecovery"=>$idrecovery));

		if(count($results) === 0){
			throw new \Exception("Não foi possivel recuperar a senha.");			
		}else{
			return $results[0];
		}

	}

	public static function setForgotUsed($idrecovery){

		$sql = new Sql;

		$sql->query("UPDATE tb_userspasswordsrecoveries SET dtrecovery = NOW() WHERE idrecovery = :idrecovery",
			array("idrecovery"=>$idrecovery));

	}

	public function setPassword($password){

		$sql = new Sql();

		$sql->query("UPDATE tb_users SET despassword = :password WHERE iduser = :iduser", array(
			":password"=>$password,
			":iduser"=>$this->getiduser()

		));

	}

}

 ?>