<?php
/*
 *	There is the rule's file
 *  @package unsyIDS
 *	@author: Luca "Unsigned" Bruzzone <luca@unsigned.it>
 *  @link: www.unsigned.it
 *  @license: http://creativecommons.org/licenses/by-nc-sa/2.5/it/deed.it CC by-nc-sa
 */

$rules = array(
		//xss filter
		  array('type' => 'xss',
		  'comment' => 'prevent malicious attribute injection',
		'regexp' => "<[^>]*(script|object|iframe|applet|meta|style|form|img|onmouseover|body)*\"?[^>]*>"),
		array('type' => 'xss',
		  'comment' => 'prevent malicious attribute injection',
		'regexp' => "([a-z]*)=([\`\'\"]*)script:"),
		array('type' => 'xss',
		  'comment' => 'prevent malicious attribute injection',
		'regexp' => "(<[^>]+)style=([\`\'\"]*).*expression\([^>]*>"),
		array('type' => 'xss',
		  'comment' => 'prevent malicious attribute injection',
		'regexp' => "(<[^>]+)style=([\`\'\"]*).*behaviour\([^>]"),
		//SQLi
		  array('type' => 'SQLi',
		  		'comment' => 'prevent mysql comments, conditions and ch(a)r injections',
		'regexp' =>'(?:"\s*(?:#|--|{))|(?:\/\*!\s?\d+)|(?:ch(?:a)?r\s*\(\s*\d)|(?:(?:(n?and|x?or|not)\s+|\|\||\&\&)\s*\w+\()'),
		array('type' => 'SQLi',
		'comment' => 'detect conditional SQL injection atempts',
		'regexp' => '(?:\)\s*like\s*\()|(?:having\s*[^\s]+\s*[^\w\s])|(?:if\s?\([\d\w]\s*[=<>~])'),
		array('type' =>'SQLi',
		'comment' => 'detect classiical SQLi',
		'regexp' => '(?:\\x(?:23|27|3d))|(?:^.?"$)|(?:^.*\\".+(?<!\\)")|(?:(?:^["\\]*(?:[\d"]+|[^"]+"))+\s*(?:n?and|x?or|not|\|\||\&\&)\s*[\w"[+&!@(),.-])|(?:[^\w\s]\w+\s*[|-]\s*"\s*\w)|(?:@\w+\s+(and|or)\s*["\d]+)|(?:@[\w-]+\s(and|or)\s*[^\w\s])|(?:[^\w\s:]\s*\d\W+[^\w\s]\s*".)'),
		array('type' =>'SQLi',
		'comment' => 'detect classical SQLi',
		'regexp' => '(?:"\s*\*.+(?:or|id)\W*"\d)|(?:\^")|(?:^[\w\s"-]+(?<=and\s)(?<=or\s)(?<=xor\s)(?<=nand\s)(?<=not\s)(?<=\|\|)(?<=\&\&)\w+\()|(?:"[\s\d]*[^\w\s]+\W*\d\W*.*["\d])|(?:"\s*[^\w\s?]+\s*[^\w\s]+\s*")|(?:"\s*[^\w\s]+\s*[\W\d].*(?:#|--))|(?:".*\*\s*\d)|(?:"\s*or\s[\w-]+.*\d)|(?:[()*<>%+-][\w-]+[^\w\s]+"[^,])'),
		array('type' => 'SQLi',
				'comment' =>'detect SQLi auth bypass 1',
				'regexp' =>'(?:\d"\s+"\s+\d)|(?:^admin\s*"|(\/\*)+"+\s?(?:--|#|\/\*|{)?)|(?:"\s*or[\w\s-]+\s*[+<>=(),-]\s*[\d"])|(?:"\s*[^\w\s]?=\s*")|(?:"\W*[+=]+\W*")|(?:"\s*[!=|][\d\s!=+-]+.*["(].*$)|(?:"\s*[!=|][\d\s!=]+.*\d+$)|(?:"\s*like\W+[\w"(])|(?:\sis\s*0\W)|(?:where\s[\s\w\.,-]+\s=)|(?:"[<>~]+")'),
		array('type' => 'SQLi',
		 'comment' =>'detect SQLi auth bypass 2',
		 'regexp' => '(?:union\s*(?:all|distinct|[(!@]*)?\s*[([]*\s*select)|(?:\w+\s+like\s+\")|(?:like\s*"\%)|(?:"\s*like\W*["\d])|(?:"\s*(?:n?and|x?or|not |\|\||\&\&)\s+[\s\w]+=\s*\w+\s*having)|(?:"\s*\*\s*\w+\W+")|(?:"\s*[^?\w\s=.,;)(]+\s*[(@"]*\s*\w+\W+\w)|(?:select\s*[\[\]()\s\w\.,-]+from)'),
		array('type' => 'SQLi',
			'comment' =>'detect SQLi auth bypass 3',
			'regexp' => '(?:(?:n?and|x?or|not |\|\||\&\&)\s+[\s\w+]+(?:regexp\s*\(|sounds\s+like\s*"|[=\d]+x))|("\s*\d\s*(?:--|#))|(?:"[%&<>^=]+\d\s*(=|or))|(?:"\W+[\w+-]+\s*=\s*\d\W+")|(?:"\s*is\s*\d.+"?\w)|(?:"\|?[\w-]{3,}[^\w\s.,]+")|(?:"\s*is\s*[\d.]+\s*\W.*")'),
		array('type' => 'SQLi',
				'comment' => 'Detects concatenated basic SQL injection and SQLLFI attempts',
				'regexp' =>'(?:^[\W\d]+\s*(?:union|select|create|rename|truncate|load|alter|delete|update|insert|desc))|(?:(?:select|create|rename|truncate|load|alter|delete|update|insert|desc)\s+(?:concat|char|load_file)\s?\(?)|(?:end\s*\);)|("\s+regexp\W)|(?:[\s(]load_file\s*\()'),
		array ('type' => 'SQLi',
				'comment' => 'Detects chained SQL injection attempts',
				'regexp'=> '(?:\/\w+;?\s+(?:having|and|or|select))|(?:\d\s+group\s+by.+\()|(?:(?:;|#|--)\s*(?:drop|alter))|(?:(?:;|#|--)\s*(?:update|insert)\s*\w{2,})|(?:[^\w]SET\s*@\w+)|(?:(?:n?and|x?or|not |\|\||\&\&)[\s(]+\w+[\s)]*[!=+]+[\s\d]*["=()])'),
		array('type'=>'SQLi',
				'comment' =>'Detects chained SQL injection attempts 2',
				'regexp' =>'(?:\*\/from)|(?:\+\s*\d+\s*\+\s*@)|(?:\w"\s*(?:[-+=|@]+\s*)+[\d(])|(?:coalesce\s*\(|@@\w+\s*[^\w\s])|(?:\W!+"\w)|(?:";\s*(?:if|while|begin))|(?:"[\s\d]+=\s*\d)|(?:order\s+by\s+if\w*\s*\()|(?:[\s(]+case\d*\W.+[tw]hen[\s(])'),
		array('type' => 'SQLi',
				'comment' => 'Detects SQL benchmark and sleep',
				'regexp' =>'(?:(select|;)\s+(?:benchmark|if|sleep)\s?\(\s?\(?\s?\w+)'),
		array('type' => 'SQLi',
				'comment' => 'Detects MySQL UDF injection and other data/structure manipulation attempts',
				'regexp' => '(?:create\s+function\s+\w+\s+returns)|(?:;\s*(?:select|create|rename|truncate|load|alter|delete|update|insert|desc)\s*[\[(]?\w{2,})'),
		array('type' => 'SQLi',
				'comment' => 'Detects MySQL charset switch and MSSQL DoS attempts',
				'regexp' => '(?:alter\s*\w+.*character\s+set\s+\w+)|(";\s*waitfor\s+time\s+")|(?:";.*:\s*goto)'),
		array('type' => 'SQLi',
				'comment' => 'Detects MySQL and PostgreSQL stored procedure/function injections',
				'regexp' => '(?:procedure\s+analyse\s*\()|(?:;\s*(declare|open)\s+[\w-]+)|(?:create\s+(procedure|function)\s*\w+\s*\(\s*\)\s*-)|(?:declare[^\w]+[@#]\s*\w+)|(exec\s*\(\s*@)'),
		//rfi
		array ('type' => 'RFI',
				 'comment' => 'prevent remote file inclusions',
				 'regexp' => '^(http|https|ftp|webdav)[\s]*:[\s]*\/[\s]*\/[\s]*.*\/.*\?'),
		//lfi
		array ('type' => 'LFI',
				 'comment' => 'prevent local file inclusions',
				 'regexp' => '\.+\/+'),
		//log poisoning
		//rule from 0xSentinel by KinG-InFeT
		array ('type' => 'Log poisoning',
				 'comment' => 'prevent remote command execution in log',
				 'regexp' => '/(<|%3C)\\?(php)?(.+)\\?>/i'),
		//write here custom regules

	  );//end of array
?>
