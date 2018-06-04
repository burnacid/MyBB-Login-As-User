<?php

if (!defined("IN_MYBB"))
    die("This file cannot be accessed directly.");

$plugins->add_hook('member_login', 'admhijack_login');
$plugins->add_hook('member_logout_start', 'admhijack_logout');
$plugins->add_hook('member_profile_end', 'admhijack_profile');
$plugins->add_hook('private_start', 'admhijack_private_start');
$plugins->add_hook('forumdisplay_start', 'admhijack_forumdisplay_start');
$plugins->add_hook('showthread_start', 'admhijack_showthread_start');


function admhijack_info()
{
    return array(
        'name' => 'Login As',
        'description' => 'Allows admins to log into another user\'s account via their profile, and quickly swap back to their account via the Logout link. Original creator <a href="http://mybbhacks.zingaburga.com/showthread.php?tid=268">ZiNgA BuRgA</a></strong>',
        'website' => '',
        'author' => 'S. Lenders (burnacid)',
        'authorsite' => 'https://lenders-it.nl',
        'version' => '2.0',
        'compatibility' => '18*',
        );
}

function admhijack_login()
{
    global $mybb;
    if (!admhijack_allowed() || $mybb->input['do'] != 'hijack' || !$mybb->input['uid'])
        return;

    verify_post_check($mybb->input['my_post_key']);
    $user = get_user(intval($mybb->input['uid']));
    if (!$user)
        error('Invalid UserID supplied.');
    my_setcookie('mybbadminuser', $mybb->user['uid'] . '_' . $mybb->user['loginkey'], null, true);
    my_setcookie('mybbuser', $user['uid'] . '_' . $user['loginkey'], null, true);

    admhijack_log_admin_action("Start controlling:" . $user['username']);

    redirect('index.php', 'You have successfully logged in as ' .
        htmlspecialchars_uni($user['username']) .
        '<br />You will be redirected to the forum index...');
    exit;
}

function admhijack_log_admin_action()
{
    global $db, $mybb;

    if ($mybb->version_code >= 1400)
        $cookies = &$mybb->cookies;
    else
        $cookies = &$_COOKIE;

    $data = func_get_args();

    if (count($data) == 1 && is_array($data[0])) {
        $data = $data[0];
    }

    if (!is_array($data)) {
        $data = array($data);
    }

    if ($cookies['mybbadminuser']) {
        $info = explode("_", $cookies['mybbadminuser']);
        $uid = (int)$info[0];
    } else {
        $uid = (int)$mybb->user['uid'];
    }

    $log_entry = array(
        "uid" => $uid,
        "ipaddress" => $db->escape_binary(my_inet_pton(get_ip())),
        "dateline" => TIME_NOW,
        "module" => "admhijack",
        "action" => "hijack-account",
        "data" => $db->escape_string(@my_serialize($data)));

    $db->insert_query("adminlog", $log_entry);
}

function admhijack_logout()
{
    global $mybb, $lang;

    if (admhijack_allowed() && $mybb->input['do'] == 'regenkey' && $mybb->input['uid']) {
        verify_post_check($mybb->input['my_post_key']);
        $user = get_user(intval($mybb->input['uid']));
        if (!$user)
            error('Invalid UserID supplied.');
        update_loginkey($user['uid']);
        redirect('member.php?action=profile&uid=' . $user['uid'],
            'You have successfully forced the selected user to log out.');
        exit;
    }

    if ($mybb->version_code >= 1400)
        $cookies = &$mybb->cookies;
    else
        $cookies = &$_COOKIE;

    if (!$cookies['mybbadminuser'])
        return;

    if (!$mybb->user['uid'])
        redirect('index.php', $lang->redirect_alreadyloggedout);
    // Check session ID if we have one
    if ($mybb->input['sid'] && $mybb->input['sid'] != $session->sid)
        error($lang->error_notloggedout);
    // Otherwise, check logoutkey
    else
        if (!$mybb->input['sid'] && $mybb->input['logoutkey'] != $mybb->user['logoutkey'])
            error($lang->error_notloggedout);
    my_setcookie('mybbuser', $cookies['mybbadminuser'], null, true);

    admhijack_log_admin_action("Stopped controlling:" . $mybb->user['username']);

    my_unsetcookie('mybbadminuser');

    redirect('member.php?action=profile&uid=' . $mybb->user['uid'],
        'You have logged out of the hijacked account and will be logged back in to your admin account.');
    exit;
}

function admhijack_profile()
{
    global $templates, $mybb;

    if (!admhijack_allowed()) {
        return;
    } else {
        if (!$templates->cache['member_profile'])
            $templates->cache('member_profile');

        $templates->cache['member_profile'] = str_replace('{$modoptions}',
            '{$modoptions}<br /><table border="0" cellspacing="{$theme[\'borderwidth\']}" cellpadding="{$theme[\'tablespace\']}" width="100%" class="tborder">
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
</table>', $templates->cache['member_profile']);
    }
}

function admhijack_allowed()
{
    global $mybb;

    $allowed = $mybb->settings['loginasgroups'];
    $othergroups = explode(",", $mybb->user['additionalgroups']);

    if ($mybb->user['usergroup'] == $allowed) {
        return true;
    } elseif (in_array($allowed, $othergroups)) {
        return true;
    } else {
        return false;
    }
}

function admhijack_private_start()
{
    global $mybb;

    $cookies = &$_COOKIE;

    if (!empty($cookies['mybbadminuser'])) {
        redirect($mybb->settings['bburl'],
            "GO AWAY... You are not allowed to look at someone else his private messages...",
            "Permissions Denied", false);
    }
}

function admhijack_forumdisplay_start()
{
    global $mybb;

    $cookies = &$_COOKIE;

    if (!empty($cookies['mybbadminuser'])) {
        $deniedfid = explode(",", $mybb->settings['loginas_deniedforums']);

        if (in_array($mybb->input['fid'], $deniedfid)) {
            redirect($mybb->settings['bburl'],
                "GO AWAY... You are not allowed to look at these forums through someone else his account...",
                "Permissions Denied", false);
        }
    }
}

function admhijack_showthread_start()
{
    global $mybb, $fid;

    $cookies = &$_COOKIE;

    if (!empty($cookies['mybbadminuser'])) {
        $deniedfid = explode(",", $mybb->settings['loginas_deniedforums']);

        if (in_array($fid, $deniedfid)) {
            redirect($mybb->settings['bburl'],
                "GO AWAY... You are not allowed to look at these forums through someone else his account...",
                "Permissions Denied", false);
        }
    }
}

?>