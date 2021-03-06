<?php
/*
*	There is the core's file
* @package unsyIDS
*	@author: Luca "Unsigned" <luca@unsigned.it>
* @link: www.unsigned.it
* @license: http://creativecommons.org/licenses/by-nc-sa/2.5/it/deed.it CC by-nc-sa
*/
function filter(){
error_reporting(0);  
require_once 'dati.php';
require_once 'rules.php';

//Concat all input parameter  
$var= array_merge ($_GET, $_POST, $_COOKIE);
array_push($var, $_SERVER['HTTP_USER_AGENT']);

//if var has no element I don't need to parse...
if (count($var) == 0) { return 0; }
if ($dati['browser_whitelist'] == 1){
	$i= 0;
	foreach ($browser_whitelist as $value){
		(preg_match("/$value/msi", $_SERVER['HTTP_USER_AGENT'])) ? $i++ : '';
	}
	($i == 0) ? die('Your browser is not supported, get a standard browser') : '';
}
//if we have all filters I don't check what filter are on
if (strcmp($dati['filters'], 'all') == 0){
 foreach($var as $value){
	 if (!is_int($value)){ //integer value can't be dangerous
		 foreach($rules as $rule){
			 //I'll check in rule if input can be dangerouse 
			 if(preg_match("/{$rule['regexp']}/msi", $value)){found();}
		 }
	 }
 }
} else {
 foreach($var as $value){
	 if (!is_int($value)){ //integer value can't be dangerous
		 foreach($rules as $rule){
			 if(preg_match("/{$dati['filters']}/msi", $rule['type'])){
				 if(preg_match("/{$rule['regexp']}/msi", $value)){
					 if($dati['alert']==1){found();}
				 }
			 }
		 }
	 }
 }
}//else
}



function found(){
include 'dati.php';
$date = gmdate(DATE_RFC822, getRealHour());
$ip = getRealIp();

if($dati['logging']==1){
 $file=fopen('log.txt', 'a+');
 fwrite($file,
	 $_SERVER ['PHP_SELF'] ." \n ".
	 $_SERVER['REQUEST_URI']." \n".
	 $_SERVER['HTTP_USER_AGENT']." \n".
	 $date." \n".
	 $ip ."\n
	  ________________________________________\n");
 fclose($file);
}

if($dati['alert']==1){
 mail($dati['email_admin'],
	 //subject
	 'unsyIDS stopped an attack',
	 //message
	 'I just stopped an attack on your site
If you have turned on the logging system you can read the list of attack stopped
Date of attack: '.$date.'
Query string: '.$_SERVER['QUERY_STRING'].'
User Agent: '.$_SERVER['HTTP_USER_AGENT'].'
Ip: '.$ip.' 
Thanks for using this software,
Have a nice day',
'X-Mailer: unsyIDS \r\n
Content-type: text; charset=iso-8859-1 \r\n,
Content-Transfer-Encoding: 8bit\n\n');
}
 
 if ($dati['alert'] == 1){ 
	?>
		 <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" 
		 "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd"> 
		 <html xmlns="http://www.w3.org/1999/xhtml" lang="it"> 
		 <head> 
		 <title>Buhahahahahaha</title> 
		 <!-- meta tag --> 
		 <meta http-equiv="Content-type" content="text/html; charset=utf-8" /> 
		 <meta http-equiv="Content-Language" content="en" /> 
		 <meta name="Keywords" content="unsigned space" /> 
		 <meta name="Owner" content="Luca \'Unsigned\' <luca@unsigned.it>" /> 
		 <meta name="Author" content="Luca \'Unsigned\' <luca@unsigned.it)" /> 
		 <meta name="distribution" content="Global" />  
		 <meta name="generator" content="Vim" /> 
		 <meta name="cms" content="unsyIDS" /> 
		 <meta name="Copyright" content="unsigned.it" /> 
		 <style> 
			body{
				background-color: #000000;
				color:#00ff00;
				text-align:center;
			}
		</style> 
		</head> 
		<body> 
		<h1>Lolz you fail</h1> 
		<p>Attack found from <?php echo $ip; ?></p>
		<p>Your browser is: <?php echo htmlentities($_SERVER['HTTP_USER_AGENT']) ?></p>
		<p>Powered by unsyIDS</p>
		</body> 
		</html>
		
		<?php
		}
		die();
	}

	function sentinel(){
		filter();
	}
	
	function getRealIp(){
		return isset($_SERVER['HTTP_X_FORWARDED_FOR']) ? $_SERVER['HTTP_X_FORWARDED_FOR'] : $_SERVER['REMOTE_ADDR'];
	}
	
	function getRealHour(){
		$socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP); 
		if (!is_resource($socket)) {
			return FALSE;
		} 
	 
		$result = socket_connect($socket, '193.204.114.105', intval(37));
		$time_tmp = socket_read($socket, 32);
		socket_close($socket);
		$time = null;
		for ($i=0;$i<4;$i++){
			$time .= intval(ord(substr($time_tmp, $i , 1)));	
		}
	return $time;
	}
	
?>
