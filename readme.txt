=== Plugin Name ===
Contributors: JWall
Donate link: http://www.forexp.net/
Tags: smf,forums,users,bridge,wordpress
Requires at least: 2.5.0
Tested up to: 3.2.1
Stable tag: 2.3

Login bridge from Simple Machine Forum to Wordpress.

== Description ==

[SMF2WP](http://www.forexp.net/category/wordpress-plugins/smf-to-wordpress-bridge-plugin/) is a simple one way bridge from Simple Machine Forum (v2.0.1 tested) to  Wordpress (v3.2.1 tested). This means, this one uses databases of SMF Forum and sync to WP database every time a user performs log-in action in both WP and SMF. To get this working, it is highly recommended that you have a fresh install of Wordpress with an install of SMF. Also, WP and SMF must be installed in same domain, and  should not be being accessed through a subdomain, though it still work.  For example,  if your website contains of Wordpress for news and SMF for forum, if your news is mydomain.com, then your forums should be somewhere like mydomain.com/forum.

This plugin will do these following tasks:

* If a user log in WP, then that user will be logged in SMF using SMF2API.
* If a user logout WP, then that user will be logged out SMF using SMF2API.
* If a user log in SMF, will be logged in WP as well.
* If a user log out SMF, will be loged out WP as well.

*IMPORTANCE*: After installation, please read OTHER NOTES for further instructions.

This new plugin only was tested by me at our organization website [vysajp.org](http://www.vysajp.org)! Please keep in mind that I am not responsible for any data loss that might occur through your use of this plugin! Please see the [plugin's website](http://www.forexp.net/category/wordpress-plugins/smf-to-wordpress-bridge-plugin/), and report bugs for a better version!

== Installation ==

You need to have a working installation of SMF, and it is preferred to have a new WP installation. You must have SMF installed as a directory within your domain. Your forum and WordPress installations should not be on different domains or subdomains! Your blog on mydomain.com and forum on forum.mydomain.com will not work!

For example, if you access your blog from www.forexp.net, your wordpress installation is at www.forexp.net/wordpress, then it is possible that you can access your forum at www.forexp.net/forum. 

1. Upload `smf2wp` to the `/wp-content/plugins/` directory
1. Uncheck "Enable local storage of cookies" and "Use subdomain independent cookie" in SMF. You can turn it off from Admin>Configuration>Server Settings...>Cookies and Sessions
1. Activate the plugin through the 'Plugins' menu in WordPress
1. Visit SMF2WP Settings in your Admin Settings section, enter relative URI to your forum, then Save it. If it is accessible, then at this point, SMF2WP is fully activated.

== Notes ==

*** I spent a lot of time for this plugin, please consider donating or at least giving me some encourage comments at my Website [SMF2WP](http://www.forexp.net/category/wordpress-plugins/smf-to-wordpress-bridge-plugin/) ***

Every time a user logged in SMF forum, same username (will be created if not exist) will be logged in  Wordpress. Because SMF is placed in higher order, so user in Wordpress will be changed to SMF with same role.

For example, you have an administrator named "admin" in wordpress, after SMF2WP fully activated, the SMF user named "admin" can login as that administrator. So be careful!

== Frequently Asked Questions ==
= I need help or found a bug! =

Go here and comment  me about it:
[SMF2WP](http://www.forexp.net/category/wordpress-plugins/smf-to-wordpress-bridge-plugin/)

= How do I active SMF2WP? =

Read Installations.

= How do I know URI to forum =

For example, if you access your blog from www.forexp.net, your wordpress installation is at www.forexp.net/wordpress, your forum at www.forexp.net/forum. Then URI will be: ../forum

If you need helps, go here and  comment  me.
[SMF2WP](http://www.forexp.net/category/wordpress-plugins/smf-to-wordpress-bridge-plugin/)

== Demo Sites ==

Well, have a look at [vysajp.org](http://www.vysajp.org/news/?p=1848)

== Changelog ==

= 2.3 =
Increase stability

= 2.2 =
Increase stability

= 2.1 =

Fix different database bugs. Thanks to NgocTu@vysa for report this bug

= 2.0 =

- Upgrade for SMF 2.x Version. Do not use SMF 1.x version with this plugin.

= 1.3 = Fix WAMP parse error bugs.

= 1.2 =

- Fix Login twice bug, thanks to Matt L.
- Change login Logic, so it may be come more stable.
- Change auto-login, auto-logout Logic
- Change plugin URL
- Fix several bugs

= 1.1 =
Change name to avoid name conflict
Fix several small bugs
Remove unwanted comment

= 1.0 =
* Based on Jonathan "JonnyFunFun" Enzinna's version

== Upgrade Notice ==

Not yet

== Screenshots ==
Demo site's available, please have a look.
