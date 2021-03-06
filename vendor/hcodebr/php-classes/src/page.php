<?php 

namespace Jonathan;

use Rain\Tpl;

class Page {

	private $tpl;
	private $options = [];
	private $default = [
		"header" => true,
		"footer" => true,
		"data" => []
	];

	public function __construct($opts = array(), $tpl = "/views/")
	{

		$this->options = array_merge($this->default, $opts);

		$config = array(
			"tpl_dir" => $_SERVER["DOCUMENT_ROOT"].$tpl,
			"cache_dir" => $_SERVER["DOCUMENT_ROOT"]."/views-cache/",
			"debug" => false
		);

		Tpl::configure($config);

		$this->tpl = new Tpl;

		$this->setData($this->options["data"]);

		if($this->options["header"])
		{
			$this->tpl->draw("header");
		}

	}

	public function setData($data = array())
	{

		foreach ($data as $key => $value) {
			$this->tpl->assign($key, $value);
		}

	}

	public function setTpl($name, $data = array(), $returnHTML = false)
	{

		$this->setData($data);
		return $this->tpl->draw($name, $returnHTML);
	}

	public function __destruct()
	{
		if($this->options["footer"])
		{
			$this->tpl->draw("footer");
		}		

	}

}

 ?>