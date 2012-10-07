<?php
/*
Plugin Name: SMF2WP
Plugin URI: http://www.forexp.net/wordpress-plugins/plugins/smf-to-wordpress-bridge-plugin-2/
Description: Login bridge from SMF, SMF based joomla, to Wordpress. Tested up to Wordpress 3.2.1 and SMF 2.0.1 RC3. Visit Plugin pages to report bugs.  
Author: JWall
Version: 2.3
Author URI: http://www.forexp.net
Demo page: http://www.forexp.net
*/

class jwall_smf2wp {
    static $bridge_active = false; //Bridge is active or not
    static $smf_dir = ''; 
    static $reg_override = 0;
    static $smf_dbopts = array();
    static $smf_settings = array();

    function version() { return 2.0; }

    /* load
     * $force: force to load, prevent overload
     */
    function load($force = false) {
			if ((self::$bridge_active) and (!$force)) return;    
			if (get_option('smf2wp_setup_complete') == 1) {
	  	  // Load the settings
	  	  self::$smf_dir = ABSPATH.get_option('smf2wp_smfdir');
	  	  self::$reg_override = (get_option('smf2wp_regoverride')) ? get_option('smf2wp_regoverride') : 0;
	  	  if (file_exists(self::$smf_dir."Settings.php"))
					require_once(self::$smf_dir."Settings.php");
	   	  else {
					delete_option('smf2wp_setup_complete');
					return false;
	    	}
	    	if (!function_exists('smf_cookie_url'))
			    require_once(dirname(__FILE__)."/smf2api.php");
			
		    global $smf_settings;
		    if ($smf_settings["globalCookies"]!="0"||$smf_settings["globalCookies"]!="0")
		    	{ 
			    	self::$bridge_active = false;		    		
		    		return false;
		    	}
	    	self::$bridge_active = true;
		    self::$smf_dbopts['user'] = $db_user;
		    self::$smf_dbopts['pass'] = $db_passwd;
		    self::$smf_dbopts['host'] = $db_server;
		    self::$smf_dbopts['prefix'] = "`".$db_name."`.".$db_prefix;
		    self::$smf_dbopts['name'] = $db_name;
		    self::$smf_settings = $smf_settings;
		    return true;
			} else return false;
    }

    function add_menu() {
	add_submenu_page('options-general.php','SMF2WP Settings','SMF2WP Settings',8,__FILE__,array('jwall_smf2wp','settings'));
    }

  function settings() {
	$prev_active = self::$bridge_active;
	echo '<div class="wrap"><h2>SMF2WP Settings</h2></div>';
	if ($_SERVER['REQUEST_METHOD'] == 'POST') {
	    // Save settings
	    switch ($_POST['action']) {
		case "save":
		    if (substr($_POST['smf_relpath'],-1) != '/')
			$_POST['smf_relpath'] = $_POST['smf_relpath'].'/';
		    if (!get_option('smf2wp_smfdir'))
			add_option('smf2wp_smfdir',$_POST['smf_relpath']);
		    else
			update_option('smf2wp_smfdir',$_POST['smf_relpath']);
		    // Double check the bridge dir before activating
		    if (file_exists(ABSPATH.get_option('smf2wp_smfdir')))
			add_option('smf2wp_setup_complete',1);
		    else
			delete_option('smf2wp_setup_complete');
		    echo '<div id="message" class="updated fade">Settings saved!</div>';
		    break;
	    }
	    self::load(true);
    	}
	if (!self::$bridge_active) {
	    // Let them know we're not fully set up!
	    echo '<div id="message" class="updated fade">SMF2WP has not been configured properly and is not active!</div>';
	} elseif ((self::$bridge_active) && ($_SERVER['REQUEST_METHOD'] == "POST") && (!$prev_active)) {
	    echo '<div id="message" class="updated fade">SMF2WP is now fully activated!</div>';
	}
	if ((get_option('smf2wp_smfdir')) && (!file_exists(ABSPATH.get_option('smf2wp_smfdir').'Settings.php')))
	    echo '<div id="message" class="updated fade">Your SMF path is invalid - could not locate Settings.php in <em>'.ABSPATH.get_option('smf2wp_smfdir').'</em></div>';
	global $smf_settings;
	if ($smf_settings["globalCookies"]!="0"||$smf_settings["localCookies"]!="0")
	    echo '<div id="message" class="updated fade">This plugin <span style="color:red">may not work</span>, because you did not uncheck "Enable local storage of cookies" and "Use subdomain independent cookie" in SMF settings!</div>';

?>
    <form action="<?php echo $_SERVER['REQUEST_URI']?>" method="POST">
	<input type="hidden" name="action" value="save"/>
	<table width="100%" cellspacing="2" cellpadding="5" class="editform">
	<tr>
	    <th width="33%" scope="row" valign="top">Forum Path:<br />
		<font style="font-size: 8px;"><em>URI relative to Wordpress root<br />
		 i.e - "forum/" places your forums in <?php echo ABSPATH?>forum/</em></font>
	    </th>
	    <td>
	    <input type="text" name="smf_relpath" value="<?php echo (get_option('smf2wp_smfdir')) ? get_option('smf2wp_smfdir') : ''?>" maxlength="256" style="width: 250px;"/>
	    </td>
	</tr>
	<tr><th colspan="2" style="color:brown; font-size:10px">You have to uncheck "Enable local storage of cookies" and "Use subdomain independent cookie" in SMF to make this plugin works<br/>You can turn it off from Admin>Configuration>Server Settings...>Cookies and Sessions</th></tr>
	<tr><td colspan="2" style="height: 18px;"></td></tr>
	<tr>
	    <td>&nbsp;</td>
	    <td>
		<input type="submit" value="Save Settings"/>
	    </td>
	</tr>
	</table>
    </form><br />

<?php
    }

    function logout() {
		if (!self::$bridge_active) return;
		if (smf_authenticateUser()) {
			global $smf_user_info;
			//var_dump($smf_user_info);die();
			$current_user = wp_get_current_user();
			if ( 0 != $current_user->ID) {
  			  smf_LogoutByIdMember($smf_user_info['id_member']);
			}
	    }
	  }

  function syncprofile($username, $password) {	    
    	global $wpdb;
		if (!self::$bridge_active) return;
  	    $smf_cxn = mysql_connect(self::$smf_dbopts['host'],self::$smf_dbopts['user'],self::$smf_dbopts['pass']) or trigger_error(mysql_error(),E_USER_ERROR);

		$SQL = "SELECT real_name, email_address FROM ".self::$smf_dbopts['prefix']."members WHERE member_name = '$username'";
		if (!$rs = mysql_query($SQL,$smf_cxn)) trigger_error(mysql_error(),E_USER_ERROR);
		if (mysql_num_rows($rs) > 0) {
		    list($rName,$eAdress) = mysql_fetch_array($rs, MYSQL_NUM);
		    //$pass = md5($password);
		    $pass = wp_hash_password($password);
		}

		$user_exists = $wpdb->get_row("SELECT id, user_pass FROM $wpdb->users WHERE user_login = '$username'");		
		if ($user_exists) {
		  // If user exists and password is true (Not changing) then return quietly
		  if (wp_check_password($password, $user_exists->user_pass)) return true; 	       
          // Or that user may have changed password in Forum...

  	      $SQL = $wpdb->prepare("UPDATE $wpdb->users SET user_pass = %s, user_nicename = %s, user_email = %s, display_name = %s WHERE user_login = %s LIMIT 1",$pass, $username, $eAdress, $rName, $username); 
		$wpdb->query($SQL);
		} else {
	  	$SQL = $wpdb->prepare("INSERT INTO $wpdb->users (user_login, user_pass, user_nicename, user_email, display_name) VALUES ('%s', '%s','%s','%s','%s')",$username,$pass,$username,$eAdress,$rName);
		$wpdb->query($SQL);
			$subscriber = 'a:1:{s:10:"subscriber";b:1;}';
  		$user_exists = $wpdb->get_row("SELECT id FROM $wpdb->users WHERE user_login = '$username'");
	  	$uid = $user_exists->id;
	  	$SQL = $wpdb->prepare("INSERT INTO $wpdb->usermeta (user_id, meta_key, meta_value) VALUES ('%s', '%s','%s')",$uid,'wp_capabilities',$subscriber);
 			$wpdb->query($SQL);
	  	$SQL = $wpdb->prepare("INSERT INTO $wpdb->usermeta (user_id, meta_key, meta_value) VALUES ('%s', '%s','%s')",$uid,'nickname',$username);
 			$wpdb->query($SQL);	  	  				
		}
  }


  function checklogin() {
  
    //Because "init" is called before "plugins_loaded", must call load()
    self::load();
		if (!self::$bridge_active) return;		
		global $smf_user_info,$scheme,$auth_cookie_name,$wpdb;
		
		if (smf_authenticateUser()) {     
			$current_user = wp_get_current_user();
			if ( 0 == $current_user->ID || $current_user->user_login!=$smf_user_info["member_name"]) {
			  self::syncprofile($smf_user_info['member_name'],wp_generate_password( 12, false ));
		      if ($user=get_userdatabylogin($smf_user_info["member_name"])){
			    // The user does not exist in the WP database - let's sync and try again				
		    	if (!$user=get_userdatabylogin($smf_user_info["member_name"])) die("MYSQL Error");
			    //Set user & Cookie		   		
    	   		wp_set_auth_cookie($user->ID);
        		do_action('wp_login', $user->user_login);				
        		wp_set_current_user($user->ID, $user->user_login);
    			//wp_redirect( home_url()."/wp-admin/" ); 
  		  	  }
			}
		} else {
			if (is_user_logged_in()){
				wp_logout();
				wp_redirect( home_url() ); 
				exit;
			}
		}
  }

  function import_auth(&$user, &$pass) {
  	global $wpdb; 
    if (!$user) return;
		if (smf_authenticate_password($user,$pass)) {
    	// Sync the password into WordPress
	  	self::syncprofile($user,$pass);
	    smf_LoginById($user);
	    wp_redirect(home_url());
		}
  }
}

/* Associate the necessary action and filter hooks */
add_action('admin_menu',array('jwall_smf2wp','add_menu'));
add_action('plugins_loaded',array('jwall_smf2wp','load'));
add_action('init',array('jwall_smf2wp','checklogin'));
add_action('wp_authenticate',array('jwall_smf2wp','import_auth'),1,2);
add_action('wp_logout',array('jwall_smf2wp','logout'));
?>
