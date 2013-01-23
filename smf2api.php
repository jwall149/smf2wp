<?php
// This is just because SMF in general hates magic quotes at runtime.
@set_magic_quotes_runtime(0);

// Hopefully the forum is in the same place as this script.
//require_once(dirname(__FILE__) . '/Settings.php');

function DebugNDie($param){
	var_dump($param);
	die();
}

global $smf_settings, $smf_user_info, $smf_connection;

$smf_settings = array();
$smf_settings['cookiename'] = $cookiename;
$smf_settings['language'] = $language;
$smf_settings['forum_name'] = $mbname;
$smf_settings['forum_url'] = $boardurl;
$smf_settings['webmaster_email'] = $webmaster_email;
$smf_settings['db_prefix'] = '`' . $db_name . '`.' . $db_prefix;

//echo "SMSSTT:"; var_dump($smf_settings); die();
// If $maintenance is set to 2, don't connect to the database at all.
if ($maintenance != 2)
{
	// Ignore connection errors, because this is just an API file.
	if (empty($db_persist))
		$smf_connection = @mysql_connect($db_server, $db_user, $db_passwd);
	else
		$smf_connection = @mysql_pconnect($db_server, $db_user, $db_passwd);

	$request = smf_query("
		SELECT variable, value
		FROM $smf_settings[db_prefix]settings", __FILE__, __LINE__);

	while ($row = @mysql_fetch_row($request))
		$smf_settings[$row[0]] = $row[1];
		
	mysql_free_result($request);
}

// Load stuff from the Settings.php file into $smf_settings.


// Actually set the login cookie...
function smf_setLoginCookie($cookie_length, $id, $password = '', $encrypted = true)
{
	// This should come from Settings.php, hopefully.
	global $smf_connection, $smf_settings;


	// The $id is not numeric; it's probably a username.
	if (!$smf_connection)
		return false;

	// It wasn't found, after all?
	if (empty($id))
	{
		$id = (int) $username;
		unset($username);
	}

	// Oh well, I guess it just was not to be...
	if (empty($id))	return false;

	// The password isn't encrypted, do so.
	if (!$encrypted)
	{
		if (!$smf_connection)
			return false;

		$result = smf_query("
			SELECT memberName, password_salt
			FROM $smf_settings[db_prefix]members
			WHERE ID_MEMBER = '" . (int) $id . "'
			LIMIT 1", __FILE__, __LINE__);
		list ($username, $salt) = mysql_fetch_row($result);
		mysql_free_result($result);

		if (empty($username))
			return false;

		//$password = sha1(sha1(strtolower($username) . $password) . $salt);
		$password = sha1($password.$salt);
	}

	function smf_cookie_url($local, $global)
	{
		// Use PHP to parse the URL, hopefully it does its job.
		global $smf_settings;
		$parsed_url = parse_url($smf_settings['forum_url']);

		// Set the cookie to the forum's path only?
		if (empty($parsed_url['path']) || !$local)
			$parsed_url['path'] = '';

		// This is probably very likely for apis and such, no?
		if ($global)
		{
			// Try to figure out where to set the cookie; this can be confused, though.
			if (preg_match('~(?:[^\.]+\.)?(.+)\z~i', $parsed_url['host'], $parts) == 1)
				$parsed_url['host'] = '.' . $parts[1];
		}
		// If both options are off, just use no host and /.
		elseif (!$local)
			$parsed_url['host'] = '';
		return $parsed_url;
	}

	// The cookie may already exist, and have been set with different options.
	$cookie_state = (empty($smf_settings['localCookies']) ? 0 : 1) | (empty($smf_settings['globalCookies']) ? 0 : 2);
	if (isset($_COOKIE[$smf_settings['cookiename']]))
	{
		$array = @unserialize($_COOKIE[$smf_settings['cookiename']]);

		if (isset($array[3]) && $array[3] != $cookie_state)
		{
			$cookie_url = smf_cookie_url($array[3] & 1 > 0, $array[3] & 2 > 0);
			setcookie($smf_settings['cookiename'], serialize(array(0, '', 0)), time() - 3600, $parsed_url['path'] . '/', $parsed_url['host'], 0);
		}
	}

	// Get the data and path to set it on.
	$data = serialize(empty($id) ? array(0, '', 0) : array($id, $password, time() + $cookie_length));

	$parsed_url = smf_cookie_url(!empty($smf_settings['localCookies']), !empty($smf_settings['globalCookies']));

//  var_dump($smf_settings);

	// Set the cookie, $_COOKIE, and session variable.
	setcookie($smf_settings['cookiename'], $data, time() + $cookie_length, $parsed_url['path'] . '/', $parsed_url['host'], 0);
	$_COOKIE[$smf_settings['cookiename']] = $data;
	$_SESSION['login_' . $smf_settings['cookiename']] = $data;

	return true;
}

function smf_authenticateUser()
{
	global $smf_connection, $smf_settings, $smf_user_info;
	//Empty $smf_user_info
  //var_dump($smf_user_info); die();
	// No connection, no authentication!
	if (!$smf_connection)
		return false;

	// Check first the cookie, then the session.
	//var_dump($_COOKIE[$smf_settings['cookiename']]); die();
	if (isset($_COOKIE[$smf_settings['cookiename']]))
	{
		$_COOKIE[$smf_settings['cookiename']] = stripslashes($_COOKIE[$smf_settings['cookiename']]);


		// Fix a security hole in PHP 4.3.9 and below...
		if (preg_match('~^a:[34]:\{i:0;(i:\d{1,6}|s:[1-8]:"\d{1,8}");i:1;s:(0|40):"([a-fA-F0-9]{40})?";i:2;[id]:\d{1,14};(i:3;i:\d;)?\}$~', $_COOKIE[$smf_settings['cookiename']]) == 1)
		{
			list ($ID_MEMBER, $password) = @unserialize($_COOKIE[$smf_settings['cookiename']]);
			$ID_MEMBER = !empty($ID_MEMBER) ? (int) $ID_MEMBER : 0;
		}
		else
			$ID_MEMBER = 0;
	}
	elseif (isset($_SESSION['login_' . $smf_settings['cookiename']]))
	{
		list ($ID_MEMBER, $password, $login_span) = @unserialize(stripslashes($_SESSION['login_' . $smf_settings['cookiename']]));
		$ID_MEMBER = !empty($ID_MEMBER) && $login_span > time() ? (int) $ID_MEMBER : 0;
	}
	else
		$ID_MEMBER = 0;

  //var_dump($ID_MEMBER); var_dump($password); var_dump($login_span); die();
  
	// Don't even bother if they have no authentication data.
	if (!empty($ID_MEMBER))
	{
		$request = smf_query("
			SELECT *
			FROM $smf_settings[db_prefix]members
			WHERE ID_MEMBER = $ID_MEMBER
			LIMIT 1", __FILE__, __LINE__);
		// Did we find 'im?  If not, junk it.
		if (mysql_num_rows($request) != 0)
		{
			// The base settings array.
			$smf_user_info = mysql_fetch_assoc($request);

			if (strlen($password) == 40)
				$check = sha1($smf_user_info['passwd'] . $smf_user_info['password_salt']) == $password;
			else
				$check = false;

			// Wrong password or not activated - either way, you're going nowhere.
			$ID_MEMBER = $check && ($smf_user_info['is_activated'] == 1 || $smf_user_info['is_activated'] == 11) ? $smf_user_info['ID_MEMBER'] : 0;
		}
		else
			$ID_MEMBER = 0;
		mysql_free_result($request);
	}	
	// The smf_groups can be used to check which user-groups the user belongs on the SMF side
	// it's very handy if you want to hide some information from wp-template etc.
    $smf_user_info['smf_groups'] = array_merge(array($smf_user_info['id_group'], $smf_user_info['id_post_group']), explode(',', $smf_user_info['additional_groups']));
/*	if (empty($ID_MEMBER))
		$smf_user_info = array('groups' => array(-1));
	else
	{
		if (empty($smf_user_info['additionalGroups']))
			$smf_user_info['groups'] = array($smf_user_info['ID_GROUP'], $smf_user_info['ID_POST_GROUP']);
		else
			$smf_user_info['groups'] = array_merge(
				array($smf_user_info['ID_GROUP'], $smf_user_info['ID_POST_GROUP']),
				explode(',', $smf_user_info['additionalGroups'])
			);
	}

	// A few things to make life easier...
	$smf_user_info['id'] = &$smf_user_info['ID_MEMBER'];
	$smf_user_info['username'] = &$smf_user_info['memberName'];
	$smf_user_info['name'] = &$smf_user_info['realName'];
	$smf_user_info['email'] = &$smf_user_info['emailAddress'];
	$smf_user_info['messages'] = &$smf_user_info['instantMessages'];
	$smf_user_info['unread_messages'] = &$smf_user_info['unreadMessages'];
	$smf_user_info['language'] = empty($smf_user_info['lngfile']) || empty($smf_settings['userLanguage']) ? $smf_settings['language'] : $smf_user_info['lngfile'];
	$smf_user_info['is_guest'] = $ID_MEMBER == 0;
	$smf_user_info['is_admin'] = in_array(1, $smf_user_info['groups']);

	// This might be set to "forum default"...
	if (empty($smf_user_info['timeFormat']))
		$smf_user_info['timeFormat'] = $smf_settings['time_format'];

	return !$smf_user_info['is_guest'];*/
	return $check;
}

function smf_registerMember($username, $email, $password, $extra_fields = array(), $theme_options = array())
{
	global $smf_settings, $smf_connection;

	// No connection means no registrations...
	if (!$smf_connection)
		return false;

	// Can't use that username.
	if (preg_match('~[<>&"\'=\\\]~', $username) === 1 || $username === '_' || $username === '|' || strpos($username, '[code') !== false || strpos($username, '[/code') !== false || strlen($username) > 25)
		return false;

	// Make sure the email is valid too.
	if (empty($email) || preg_match('~^[0-9A-Za-z=_+\-/][0-9A-Za-z=_\'+\-/\.]*@[\w\-]+(\.[\w\-]+)*(\.[\w]{2,6})$~', $email) === 0 || strlen($email) > 255)
		return false;

	// !!! Validate username isn't already used?  Validate reserved, etc.?

	$register_vars = array(
		'memberName' => "'$username'",
		'realName' => "'$username'",
		'emailAddress' => "'" . addslashes($email) . "'",
		'passwd' => "'" . sha1(strtolower($username) . $password) . "'",
		'password_salt' => "'" . substr(md5(mt_rand()), 0, 4) . "'",
		'posts' => '0',
		'dateRegistered' => (string) time(),
		'is_activated' => '1',
		'personalText' => "'" . addslashes($smf_settings['default_personalText']) . "'",
		'pm_email_notify' => '1',
		'ID_THEME' => '0',
		'ID_POST_GROUP' => '4',
		'lngfile' => "''",
		'buddy_list' => "''",
		'pm_ignore_list' => "''",
		'messageLabels' => "''",
		'websiteTitle' => "''",
		'websiteUrl' => "''",
		'location' => "''",
		'ICQ' => "''",
		'AIM' => "''",
		'YIM' => "''",
		'MSN' => "''",
		'timeFormat' => "''",
		'signature' => "''",
		'avatar' => "''",
		'usertitle' => "''",
		'memberIP' => "''",
		'memberIP2' => "''",
		'secretQuestion' => "''",
		'secretAnswer' => "''",
		'validation_code' => "''",
		'additionalGroups' => "''",
		'smileySet' => "''",
		'password_salt' => "''",
	);

	$register_vars = $extra_fields + $register_vars;

	smf_query("
		INSERT INTO $smf_settings[db_prefix]members
			(" . implode(', ', array_keys($register_vars)) . ")
		VALUES (" . implode(', ', $register_vars) . ')', __FILE__, __LINE__);
	$ID_MEMBER = smf_insert_id();

	smf_query("
		UPDATE $smf_settings[db_prefix]settings
		SET value = value + 1
		WHERE variable = 'totalMembers'
		LIMIT 1", __FILE__, __LINE__);
	smf_query("
		REPLACE INTO $smf_settings[db_prefix]settings
			(variable, value)
		VALUES ('latestMember', $ID_MEMBER),
			('latestRealName', '$username')", __FILE__, __LINE__);
	smf_query("
		UPDATE {$db_prefix}log_activity
		SET registers = registers + 1
		WHERE date = '" . strftime('%Y-%m-%d') . "'
		LIMIT 1", __FILE__, __LINE__);
	if (smf_affected_rows() == 0)
		smf_query("
			INSERT IGNORE INTO {$db_prefix}log_activity
				(date, registers)
			VALUES ('" . strftime('%Y-%m-%d') . "', 1)", __FILE__, __LINE__);

	// Theme variables too?
	if (!empty($theme_options))
	{
		$setString = '';
		foreach ($theme_options as $var => $val)
			$setString .= "
				($memberID, SUBSTRING('$var', 1, 255), SUBSTRING('$val', 1, 65534)),";
		smf_query("
			INSERT INTO $smf_settings[db_prefix]themes
				(ID_MEMBER, variable, value)
			VALUES " . substr($setString, 0, -1), __FILE__, __LINE__);
	}

	return $ID_MEMBER;
}

// Log the current user online.
function smf_logOnline($action = null)
{
	global $smf_settings, $smf_connection, $smf_user_info;

	if (!$smf_connection)
		return false;

	// Determine number of seconds required.
	$lastActive = $smf_settings['lastActive'] * 60;

	// Don't mark them as online more than every so often.
	if (empty($_SESSION['log_time']) || $_SESSION['log_time'] < (time() - 8))
		$_SESSION['log_time'] = time();
	else
		return;

	$serialized = $_GET;
	$serialized['USER_AGENT'] = $_SERVER['HTTP_USER_AGENT'];
	unset($serialized['sesc']);
	if ($action !== null)
		$serialized['action'] = $action;

	$serialized = addslashes(serialize($serialized));

	// Guests use 0, members use ID_MEMBER.
	if ($smf_user_info['is_guest'])
	{
		smf_query("
			DELETE FROM $smf_settings[db_prefix]log_online
			WHERE logTime < NOW() - INTERVAL $lastActive SECOND OR session = 'ip$_SERVER[REMOTE_ADDR]'", __FILE__, __LINE__);
		smf_query("
			INSERT IGNORE INTO $smf_settings[db_prefix]log_online
				(session, ID_MEMBER, ip, url)
			VALUES ('ip$_SERVER[REMOTE_ADDR]', 0, IFNULL(INET_ATON('$_SERVER[REMOTE_ADDR]'), 0), '$serialized')", __FILE__, __LINE__);
	}
	else
	{
		smf_query("
			DELETE FROM $smf_settings[db_prefix]log_online
			WHERE logTime < NOW() - INTERVAL $lastActive SECOND OR ID_MEMBER = $smf_user_info[id] OR session = '" . @session_id() . "'", __FILE__, __LINE__);
		smf_query("
			INSERT IGNORE INTO $smf_settings[db_prefix]log_online
				(session, ID_MEMBER, ip, url)
			VALUES ('" . @session_id() . "', $smf_user_info[id], IFNULL(INET_ATON('$_SERVER[REMOTE_ADDR]'), 0), '$serialized')", __FILE__, __LINE__);
	}
}

function smf_isOnline($user)
{
	global $smf_settings, $smf_connection;

	if (!$smf_connection)
		return false;

	$result = smf_query("
		SELECT lo.ID_MEMBER
		FROM $smf_settings[db_prefix]log_online AS lo" . (!is_integer($user) ? "
			LEFT JOIN $smf_settings[db_prefix]members AS mem ON (mem.ID_MEMBER = lo.ID_MEMBER)" : '') . "
		WHERE lo.ID_MEMBER = " . (int) $user . (!is_integer($user) ? " OR mem.memberName = '$user'" : '') . "
		LIMIT 1", __FILE__, __LINE__);
	$return = mysql_num_rows($result) != 0;
	mysql_free_result($result);

	return $return;
}

// Log an error, if the option is on.
function smf_logError($error_message, $file = null, $line = null)
{
	global $smf_settings, $smf_connection;

	// Check if error logging is actually on and we're connected...
	if (empty($smf_settings['enableErrorLogging']) || !$smf_connection)
		return $error_message;

	// Basically, htmlspecialchars it minus &. (for entities!)
	$error_message = strtr($error_message, array('<' => '&lt;', '>' => '&gt;', '"' => '&quot;'));
	$error_message = strtr($error_message, array('&lt;br /&gt;' => '<br />', '&lt;b&gt;' => '<b>', '&lt;/b&gt;' => '</b>', "\n" => '<br />'));

	// Add a file and line to the error message?
	if ($file != null)
		$error_message .= '<br />' . $file;
	if ($line != null)
		$error_message .= '<br />' . $line;

	// Just in case there's no ID_MEMBER or IP set yet.
	if (empty($smf_user_info['id']))
		$smf_user_info['id'] = 0;

	// Insert the error into the database.
	smf_query("
		INSERT INTO $smf_settings[db_prefix]log_errors
			(ID_MEMBER, logTime, ip, url, message, session)
		VALUES ($smf_user_info[id], " . time() . ", SUBSTRING('$_SERVER[REMOTE_ADDR]', 1, 16), SUBSTRING('" . (empty($_SERVER['QUERY_STRING']) ? '' : addslashes(htmlspecialchars('?' . $_SERVER['QUERY_STRING']))) . "', 1, 65534), SUBSTRING('" . addslashes($error_message) . "', 1, 65534), SUBSTRING('" . @session_id() . "', 1, 32))", __FILE__, __LINE__);

	// Return the message to make things simpler.
	return $error_message;
}

// Format a time to make it look purdy.
function smf_formatTime($logTime)
{
	global $smf_user_info, $smf_settings;

	// Offset the time - but we can't have a negative date!
	$time = max($logTime + (@$smf_user_info['timeOffset'] + $smf_settings['time_offset']) * 3600, 0);

	// Format some in caps, and then any other characters..
	return strftime(strtr(!empty($smf_user_info['timeFormat']) ? $smf_user_info['timeFormat'] : $smf_settings['time_format'], array('%a' => ucwords(strftime('%a', $time)), '%A' => ucwords(strftime('%A', $time)), '%b' => ucwords(strftime('%b', $time)), '%B' => ucwords(strftime('%B', $time)))), $time);
}

// Do a query, and if it fails log an error in the SMF error log.
function smf_query($string, $file, $line)
{
	global $smf_settings, $smf_connection;

	if (!$smf_connection)
		return false;

	$smf_settings['db_count'] = @$smf_settings['db_count'] + 1;

	$ret = mysql_query($string, $smf_connection);

	if ($ret === false)
		smf_logError(mysql_error($smf_connection), $file, $line);

	return $ret;
}

function smf_affected_rows()
{
	global $smf_connection;

	return mysql_affected_rows($smf_connection);
}

function smf_insert_id()
{
	global $smf_connection;

	return mysql_insert_id($smf_connection);
}

// Mother, may I?
function smf_allowedTo($permission)
{
	global $smf_settings, $smf_user_info, $smf_connection;

	if (!$smf_connection)
		return null;

	// Administrators can do all, and everyone can do nothing.
	if ($smf_user_info['is_admin'] || empty($permission))
		return true;

	if (!isset($smf_user_info['permissions']))
	{
		$result = smf_query("
			SELECT permission, addDeny
			FROM $smf_settings[db_prefix]permissions
			WHERE ID_GROUP IN (" . implode(', ', $smf_user_info['groups']) . ")", __FILE__, __LINE__);
		$removals = array();
		$smf_user_info['permissions'] = array();
		while ($row = mysql_fetch_assoc($result))
		{
			if (empty($row['addDeny']))
				$removals[] = $row['permission'];
			else
				$smf_user_info['permissions'][] = $row['permission'];
		}
		mysql_free_result($result);

		// And now we get rid of the removals ;).
		if (!empty($smf_settings['permission_enable_deny']))
			$smf_user_info['permissions'] = array_diff($smf_user_info['permissions'], $removals);
	}

	// So.... can you?
	if (!is_array($permission) && in_array($permission, $smf_user_info['permissions']))
		return true;
	elseif (is_array($permission) && count(array_intersect($permission, $smf_user_info['permissions'])) != 0)
		return true;
	else
		return false;
}

function smf_loadThemeData($ID_THEME = 0)
{
	global $smf_settings, $smf_user_info, $smf_connection;

	if (!$smf_connection)
		return null;

	// The theme was specified by parameter.
	if (!empty($ID_THEME))
		$theme = (int) $ID_THEME;
	// The theme was specified by REQUEST.
	elseif (!empty($_REQUEST['theme']))
	{
		$theme = (int) $_REQUEST['theme'];
		$_SESSION['ID_THEME'] = $theme;
	}
	// The theme was specified by REQUEST... previously.
	elseif (!empty($_SESSION['ID_THEME']))
		$theme = (int) $_SESSION['ID_THEME'];
	// The theme is just the user's choice. (might use ?board=1;theme=0 to force board theme.)
	elseif (!empty($smf_user_info['theme']) && !isset($_REQUEST['theme']))
		$theme = $smf_user_info['theme'];
	// The theme is the forum's default.
	else
		$theme = $smf_settings['theme_guests'];

	// Verify the ID_THEME... no foul play.
	if (empty($smf_settings['theme_default']) && $theme == 1 && $ID_THEME != 1)
		$theme = $smf_settings['theme_guests'];
	elseif (!empty($smf_settings['knownThemes']) && !empty($smf_settings['theme_allow']))
	{
		$themes = explode(',', $smf_settings['knownThemes']);
		if (!in_array($theme, $themes))
			$theme = $smf_settings['theme_guests'];
		else
			$theme = (int) $theme;
	}
	else
		$theme = (int) $theme;

	$member = empty($smf_user_info['id']) ? -1 : $smf_user_info['id'];

	// Load variables from the current or default theme, global or this user's.
	$result = smf_query("
		SELECT variable, value, ID_MEMBER, ID_THEME
		FROM $smf_settings[db_prefix]themes
		WHERE ID_MEMBER IN (-1, 0, $member)
			AND ID_THEME" . ($theme == 1 ? ' = 1' : " IN ($theme, 1)"), __FILE__, __LINE__);
	// Pick between $smf_settings['theme'] and $smf_user_info['theme'] depending on whose data it is.
	$themeData = array(0 => array(), $member => array());
	while ($row = mysql_fetch_assoc($result))
	{
		// If this is the themedir of the default theme, store it.
		if (in_array($row['variable'], array('theme_dir', 'theme_url', 'images_url')) && $row['ID_THEME'] == '1' && empty($row['ID_MEMBER']))
			$themeData[0]['default_' . $row['variable']] = $row['value'];

		// If this isn't set yet, is a theme option, or is not the default theme..
		if (!isset($themeData[$row['ID_MEMBER']][$row['variable']]) || $row['ID_THEME'] != '1')
			$themeData[$row['ID_MEMBER']][$row['variable']] = substr($row['variable'], 0, 5) == 'show_' ? $row['value'] == '1' : $row['value'];
	}
	mysql_free_result($result);

	$smf_settings['theme'] = $themeData[0];
	$smf_user_info['theme'] = $themeData[$member];

	if (!empty($themeData[-1]))
		foreach ($themeData[-1] as $k => $v)
		{
			if (!isset($smf_user_info['theme'][$k]))
				$smf_user_info['theme'][$k] = $v;
		}

	$smf_settings['theme']['theme_id'] = $theme;

	$smf_settings['theme']['actual_theme_url'] = $smf_settings['theme']['theme_url'];
	$smf_settings['theme']['actual_images_url'] = $smf_settings['theme']['images_url'];
	$smf_settings['theme']['actual_theme_dir'] = $smf_settings['theme']['theme_dir'];
}

// Attempt to start the session, unless it already has been.
function smf_loadSession()
{
	global $HTTP_SESSION_VARS, $smf_connection, $smf_settings, $smf_user_info;

	// Attempt to change a few PHP settings.
	@ini_set('session.use_cookies', true);
	@ini_set('session.use_only_cookies', false);
	@ini_set('arg_separator.output', '&amp;');

	// If it's already been started... probably best to skip this.
	if ((@ini_get('session.auto_start') == 1 && !empty($smf_settings['databaseSession_enable'])) || session_id() == '')
	{
		// Attempt to end the already-started session.
		if (@ini_get('session.auto_start') == 1)
			@session_write_close();

		// This is here to stop people from using bad junky PHPSESSIDs.
		if (isset($_REQUEST[session_name()]) && preg_match('~^[A-Za-z0-9]{32}$~', $_REQUEST[session_name()]) == 0 && !isset($_COOKIE[session_name()]))
			$_COOKIE[session_name()] = md5(md5('smf_sess_' . time()) . mt_rand());

		// Use database sessions?
		if (!empty($smf_settings['databaseSession_enable']) && $smf_connection)
			session_set_save_handler('smf_sessionOpen', 'smf_sessionClose', 'smf_sessionRead', 'smf_sessionWrite', 'smf_sessionDestroy', 'smf_sessionGC');
		elseif (@ini_get('session.gc_maxlifetime') <= 1440 && !empty($smf_settings['databaseSession_lifetime']))
			@ini_set('session.gc_maxlifetime', max($smf_settings['databaseSession_lifetime'], 60));

		session_start();
	}

	// While PHP 4.1.x should use $_SESSION, it seems to need this to do it right.
	if (@version_compare(PHP_VERSION, '4.2.0') == -1)
		$HTTP_SESSION_VARS['smf_php_412_bugfix'] = true;

	// Set the randomly generated code.
	if (!isset($_SESSION['rand_code']))
		$_SESSION['rand_code'] = md5(session_id() . mt_rand());
	$smf_user_info['session_id'] = &$_SESSION['rand_code'];

	if (!isset($_SESSION['USER_AGENT']))
		$_SESSION['USER_AGENT'] = $_SERVER['HTTP_USER_AGENT'];
}

function smf_sessionOpen($save_path, $session_name)
{
	return true;
}

function smf_sessionClose()
{
	return true;
}

function smf_sessionRead($session_id)
{
	global $smf_settings;

	if (preg_match('~^[A-Za-z0-9]{16,32}$~', $session_id) == 0)
		return false;

	// Look for it in the database.
	$result = smf_query("
		SELECT data
		FROM $smf_settings[db_prefix]sessions
		WHERE session_id = '" . addslashes($session_id) . "'
		LIMIT 1", __FILE__, __LINE__);
	list ($sess_data) = mysql_fetch_row($result);
	mysql_free_result($result);

	return $sess_data;
}

function smf_sessionWrite($session_id, $data)
{
	global $smf_settings, $smf_connection;

	if (preg_match('~^[A-Za-z0-9]{16,32}$~', $session_id) == 0)
		return false;

	// First try to update an existing row...
	$result = smf_query("
		UPDATE $smf_settings[db_prefix]sessions
		SET data = '" . addslashes($data) . "', last_update = " . time() . "
		WHERE session_id = '" . addslashes($session_id) . "'
		LIMIT 1", __FILE__, __LINE__);

	// If that didn't work, try inserting a new one.
	if (mysql_affected_rows($smf_connection) == 0)
		$result = smf_query("
			INSERT IGNORE INTO $smf_settings[db_prefix]sessions
				(session_id, data, last_update)
			VALUES ('" . addslashes($session_id) . "', '" . addslashes($data) . "', " . time() . ")", __FILE__, __LINE__);

	return $result;
}

function smf_sessionDestroy($session_id)
{
	global $smf_settings;

	if (preg_match('~^[A-Za-z0-9]{16,32}$~', $session_id) == 0)
		return false;

	// Just delete the row...
	return smf_query("
		DELETE FROM $smf_settings[db_prefix]sessions
		WHERE session_id = '" . addslashes($session_id) . "'
		LIMIT 1", __FILE__, __LINE__);
}

function smf_sessionGC($max_lifetime)
{
	global $smf_settings;

	// Just set to the default or lower?  Ignore it for a higher value. (hopefully)
	if ($max_lifetime <= 1440 && !empty($smf_settings['databaseSession_lifetime']))
		$max_lifetime = max($smf_settings['databaseSession_lifetime'], 60);

	// Clean up ;).
	return smf_query("
		DELETE FROM $smf_settings[db_prefix]sessions
		WHERE last_update < " . (time() - $max_lifetime), __FILE__, __LINE__);
}

// Define the sha1 function, if it doesn't exist (but the built in one would be faster.)
if (!function_exists('sha1'))
{
	function sha1($str)
	{
		// If we have mhash loaded in, use it instead!
		if (function_exists('mhash') && defined('MHASH_SHA1'))
			return bin2hex(mhash(MHASH_SHA1, $str));

		$nblk = (strlen($str) + 8 >> 6) + 1;
		$blks = array_pad(array(), $nblk * 16, 0);

		for ($i = 0; $i < strlen($str); $i++)
			$blks[$i >> 2] |= ord($str{$i}) << (24 - ($i % 4) * 8);

		$blks[$i >> 2] |= 0x80 << (24 - ($i % 4) * 8);

		return sha1_core($blks, strlen($str) * 8);
	}

	// This is the core SHA-1 calculation routine, used by sha1().
	function sha1_core($x, $len)
	{
		@$x[$len >> 5] |= 0x80 << (24 - $len % 32);
		$x[(($len + 64 >> 9) << 4) + 15] = $len;

		$w = array();
		$a = 1732584193;
		$b = -271733879;
		$c = -1732584194;
		$d = 271733878;
		$e = -1009589776;

		for ($i = 0, $n = count($x); $i < $n; $i += 16)
		{
			$olda = $a;
			$oldb = $b;
			$oldc = $c;
			$oldd = $d;
			$olde = $e;

			for ($j = 0; $j < 80; $j++)
			{
				if ($j < 16)
					$w[$j] = @$x[$i + $j];
				else
					$w[$j] = sha1_rol($w[$j - 3] ^ $w[$j - 8] ^ $w[$j - 14] ^ $w[$j - 16], 1);

				$t = sha1_rol($a, 5) + sha1_ft($j, $b, $c, $d) + $e + $w[$j] + sha1_kt($j);
				$e = $d;
				$d = $c;
				$c = sha1_rol($b, 30);
				$b = $a;
				$a = $t;
			}

			$a += $olda;
			$b += $oldb;
			$c += $oldc;
			$d += $oldd;
			$e += $olde;
		}

		return dechex($a) . dechex($b) . dechex($c) . dechex($d) . dechex($e);
	}

	function sha1_ft($t, $b, $c, $d)
	{
		if ($t < 20)
			return ($b & $c) | ((~$b) & $d);
		if ($t < 40)
			return $b ^ $c ^ $d;
		if ($t < 60)
			return ($b & $c) | ($b & $d) | ($c & $d);

		return $b ^ $c ^ $d;
	}

	function sha1_kt($t)
	{
		return $t < 20 ? 1518500249 : ($t < 40 ? 1859775393 : ($t < 60 ? -1894007588 : -899497514));
	}

	function sha1_rol($num, $cnt)
	{
		$z = 0x80000000;
		if ($z & $num)
			$a = ($num >> 1 & (~$z | 0x40000000)) >> (31 - $cnt);
		else
			$a = $num >> (32 - $cnt);

		return ($num << $cnt) | $a;
	}
}

// Log in user by user name - Added by Jwall
function smf_LoginById($username, $cookieLength = 3600){

	global $smf_connection, $smf_settings;	

	// enable binary look up for MODx workaround - Raymond
	$binaryLookup = '';

     $sql = "SELECT *
          FROM $smf_settings[db_prefix]members 
          WHERE $binaryLookup member_name = '".mysql_escape_string($username)."'
          LIMIT 1";
     $request = smf_query($sql, __FILE__, __LINE__);
     $smf_user = mysql_fetch_assoc($request);
     
    //Now login
    smf_setLoginCookie($cookieLength, $smf_user['id_member'], sha1($smf_user['passwd'] . $smf_user['password_salt']));
    return smf_authenticateUser();
}

// Log out user
function smf_LogoutByIdMember($id_member){

	global $smf_connection, $smf_settings;	

	function smf_cookie_url($local, $global)
	{
		global $smf_settings;		
		// Use PHP to parse the URL, hopefully it does its job.
		$parsed_url = parse_url($smf_settings['forum_url']);

		// Set the cookie to the forum's path only?
		if (empty($parsed_url['path']) || !$local)
			$parsed_url['path'] = '';

		// This is probably very likely for apis and such, no?
		if ($global)
		{
			// Try to figure out where to set the cookie; this can be confused, though.
			if (preg_match('~(?:[^\.]+\.)?(.+)\z~i', $parsed_url['host'], $parts) == 1)
				$parsed_url['host'] = '.' . $parts[1];
		}		
		// If both options are off, just use no host and /.
		elseif (!$local)
			$parsed_url['host'] = '';
		
		return $parsed_url;
	}

	// shouldn't have to do this but it works like charm !!
	$sql = "DELETE FROM $smf_settings[db_prefix]log_online WHERE ID_MEMBER = '$id_member' LIMIT 1";
	$request = smf_query($sql, __FILE__, __LINE__);
	
    unset($_SESSION['login_' . $smf_settings['cookiename']]);

	$PHPSESSID = $HTTP_COOKIE_VARS["PHPSESSID"];

	$parsed_url = smf_cookie_url(!empty($smf_settings['localCookies']), !empty($smf_settings['globalCookies']));
		
	setcookie("PHPSESSID", $PHPSESSID, time() - 3600, $parsed_url['path'] . '/', $parsed_url['host'], 0);  
	setcookie($smf_settings['cookiename'], "", time() - 3600, $parsed_url['path'] . '/', $parsed_url['host'], 0);   

}

function smf_authenticate_password($username,$password){
	global $smf_connection, $smf_settings;	

	// enable binary look up for MODx workaround - Raymond
	$binaryLookup = '';

     $sql = "SELECT *  
     		 FROM $smf_settings[db_prefix]members 
	         WHERE $binaryLookup member_name = '".mysql_escape_string($username)."'";
     $request = smf_query($sql, __FILE__, __LINE__);
     if($request) {
		 	$smf_user = mysql_fetch_assoc($request);  

      if (sha1(strtolower($username) . $password) == $smf_user['passwd']) return true;
	                   
      //For joomla
      if (md5($password) == $smf_user['passwd']) return true;

      list($ahash, $asalt) = explode(':', $smf_user['passwd']);
      if (strpos($smf_user['passwd'], ':') !== false)
        if ($ahash == md5($password.$asalt)) return true;
	 
     } 
		return false;
}
?>
