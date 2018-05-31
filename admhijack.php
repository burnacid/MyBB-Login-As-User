<?php

if(!defined("IN_MYBB"))
	die("This file cannot be accessed directly.");

$plugins->add_hook('member_login', 'admhijack_login');
$plugins->add_hook('member_logout_start', 'admhijack_logout');
$plugins->add_hook('member_profile_end', 'admhijack_profile');

function admhijack_info()
{
	return array(
		'name'			=> 'Admins can log into Users\' accounts',
		'description'	=> 'Allows admins to log into another user\'s account via their profile, and quickly swap back to their account via the Logout link.',
		'website'		=> 'http://mybbhacks.zingaburga.com/',
		'author'		=> 'ZiNgA BuRgA',
		'authorsite'	=> 'http://zingaburga.com/',
		'version'		=> '1.2',
		'compatibility'	=> '1*',
		'guid'			=> '8a4c3db281e87508c50386874e650297'
	);
}

function admhijack_login()
{
	global $mybb;
	if(($mybb->usergroup['cancp'] != 'yes' && $mybb->usergroup['cancp'] != 1) || $mybb->input['do'] != 'hijack' || !$mybb->input['uid'])
		return;
	
	verify_post_check($mybb->input['my_post_key']);
	$user = get_user(intval($mybb->input['uid']));
	if(!$user) error('Invalid UserID supplied.');
	my_setcookie('mybbadminuser', $mybb->user['uid'].'_'.$mybb->user['loginkey'], null, true);
	my_setcookie('mybbuser', $user['uid'].'_'.$user['loginkey'], null, true);
	redirect('index.php', 'You have successfully logged in as '.htmlspecialchars_uni($user['username']).'<br />You will be redirected to the forum index...');
	exit;
}

function admhijack_logout()
{
	global $mybb, $lang;
	
	if(($mybb->usergroup['cancp'] == 'yes' || $mybb->usergroup['cancp'] == 1) && $mybb->input['do'] == 'regenkey' && $mybb->input['uid'])
	{
		verify_post_check($mybb->input['my_post_key']);
		$user = get_user(intval($mybb->input['uid']));
		if(!$user) error('Invalid UserID supplied.');
		update_loginkey($user['uid']);
		redirect('member.php?action=profile&uid='.$user['uid'], 'You have successfully forced the selected user to log out.');
		exit;
	}
	
	if($mybb->version_code >= 1400)
		$cookies =& $mybb->cookies;
	else
		$cookies =& $_COOKIE;
	
	if(!$cookies['mybbadminuser'])
		return;
	
	if(!$mybb->user['uid'])
		redirect('index.php', $lang->redirect_alreadyloggedout);
	// Check session ID if we have one
	if($mybb->input['sid'] && $mybb->input['sid'] != $session->sid)
		error($lang->error_notloggedout);
	// Otherwise, check logoutkey
	else if(!$mybb->input['sid'] && $mybb->input['logoutkey'] != $mybb->user['logoutkey'])
		error($lang->error_notloggedout);
	my_setcookie('mybbuser', $cookies['mybbadminuser'], null, true);
	my_unsetcookie('mybbadminuser');
	
	redirect('member.php?action=profile&uid='.$mybb->user['uid'], 'You have logged out of the hijacked account and will be logged back in to your admin account.');
	exit;
}

function admhijack_profile()
{
	global $templates, $mybb;
	if($mybb->usergroup['cancp'] != 'yes' && $mybb->usergroup['cancp'] != 1)
		return;
	
	if(!$templates->cache['member_profile'])
		$templates->cache('member_profile');
	
	$templates->cache['member_profile'] = str_replace('{$modoptions}','{$modoptions}<br /><table border="0" cellspacing="{$theme[\'borderwidth\']}" cellpadding="{$theme[\'tablespace\']}" width="100%" class="tborder">
<tr>
<td colspan="2" class="thead"><strong>Admin Options</strong></td>
</tr>
<tr>
<td class="trow1">
<ul>
<li><a href="{$mybb->settings[\'bburl\']}/member.php?action=login&amp;do=hijack&amp;uid={$uid}&amp;my_post_key={$mybb->post_code}">Log in as this user</a></li>
<li><a href="{$mybb->settings[\'bburl\']}/member.php?action=logout&amp;do=regenkey&amp;uid={$uid}&amp;my_post_key={$mybb->post_code}">Force this user to log out (if logged in)</a></li>
</ul>
</td>
</tr>
</table>',$templates->cache['member_profile']);
}

?>