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
    global $lang;
    $lang->load('admhijack');

    return array(
        'name' => $lang->admhijack_name,
        'description' => $lang->admhijack_desc,
        'website' => '',
        'author' => 'S. Lenders (burnacid)',
        'authorsite' => 'https://lenders-it.nl',
        'version' => '2.0',
        'compatibility' => '18*',
        );
}

function admhijack_activate()
{
    global $db, $lang;
    $lang->load('admhijack');

    // Settings group array details
    $group = array(
        'name' => 'loginas',
        'title' => $db->escape_string($lang->setting_group_admhijack),
        'description' => $db->escape_string($lang->setting_group_admhijack_desc),
        'isdefault' => 0);

    // Check if the group already exists.
    $query = $db->simple_select('settinggroups', 'gid', "name='loginas'");

    if ($gid = (int)$db->fetch_field($query, 'gid')) {
        // We already have a group. Update title and description.
        $db->update_query('settinggroups', $group, "gid='{$gid}'");
    } else {
        // We don't have a group. Create one with proper disporder.
        $query = $db->simple_select('settinggroups', 'MAX(disporder) AS disporder');
        $disporder = (int)$db->fetch_field($query, 'disporder');

        $group['disporder'] = ++$disporder;

        $gid = (int)$db->insert_query('settinggroups', $group);
    }

    // Deprecate all the old entries.
    $db->update_query('settings', array('description' => 'ADHIJACKDELETEMARKER'),
        "gid='{$gid}'");

    // add settings
    $settings = array('deniedforums' => array('optionscode' => 'forumselect',
                'value' => ''), 'loginasgroups' => array('optionscode' => 'groupselect', 'value' =>
                '4'));

    $disporder = 0;

    // Create and/or update settings.
    foreach ($settings as $key => $setting) {
        // Prefix all keys with group name.
        $key = "admhijack_{$key}";

        $lang_var_title = "setting_{$key}";
        $lang_var_description = "setting_{$key}_desc";

        $setting['title'] = $lang->{$lang_var_title};
        $setting['description'] = $lang->{$lang_var_description};

        // Filter valid entries.
        $setting = array_intersect_key($setting, array(
            'title' => 0,
            'description' => 0,
            'optionscode' => 0,
            'value' => 0,
            ));

        // Escape input values.
        $setting = array_map(array($db, 'escape_string'), $setting);

        // Add missing default values.
        ++$disporder;

        $setting = array_merge(array(
            'description' => '',
            'optionscode' => 'yesno',
            'value' => 0,
            'disporder' => $disporder), $setting);

        $setting['name'] = $db->escape_string($key);
        $setting['gid'] = $gid;

        // Check if the setting already exists.
        $query = $db->simple_select('settings', 'sid', "gid='{$gid}' AND name='{$setting['name']}'");

        if ($sid = $db->fetch_field($query, 'sid')) {
            // It exists, update it, but keep value intact.
            unset($setting['value']);
            $db->update_query('settings', $setting, "sid='{$sid}'");
        } else {
            // It doesn't exist, create it.
            $db->insert_query('settings', $setting);
            // Maybe use $db->insert_query_multiple somehow
        }
    }

    // Delete deprecated entries.
    $db->delete_query('settings', "gid='{$gid}' AND description='ADHIJACKDELETEMARKER'");

    // This is required so it updates the settings.php file as well and not only the database - they must be synchronized!
    rebuild_settings();
}

function admhijack_deactivate()
{
    global $db, $lang;

    // Delete settings group
    $db->delete_query('settinggroups', "name='loginas'");

    // Remove the settings
    $db->delete_query('settings', "name LIKE 'admhijack_*%'");

    // This is required so it updates the settings.php file as well and not only the database - they must be synchronized!
    rebuild_settings();
}

function admhijack_login()
{
    global $mybb, $lang;
    $lang->load('admhijack');
    
    if (!admhijack_allowed() || $mybb->input['do'] != 'hijack' || !$mybb->input['uid'])
        return;

    verify_post_check($mybb->input['my_post_key']);
    $user = get_user(intval($mybb->input['uid']));
    if (!$user)
        error($lang->admhijack_invalid_uid);
    my_setcookie('mybbadminuser', $mybb->user['uid'] . '_' . $mybb->user['loginkey'], null, true);
    my_setcookie('mybbuser', $user['uid'] . '_' . $user['loginkey'], null, true);

    admhijack_log_admin_action($lang->admhijack_start_controlling . ": " . $user['username']);

    redirect('index.php', $lang->admhijack_login_success . ' ' .
        htmlspecialchars_uni($user['username']) . '<br /> ' . $lang->
        admhijack_redirect_index);
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
    $lang->load('admhijack');

    if (admhijack_allowed() && $mybb->input['do'] == 'regenkey' && $mybb->input['uid']) {
        verify_post_check($mybb->input['my_post_key']);
        $user = get_user(intval($mybb->input['uid']));
        if (!$user)
            error($lang->admhijack_invalid_uid);
        update_loginkey($user['uid']);
        redirect('member.php?action=profile&uid=' . $user['uid'], $lang->
            admhijack_force_logoff_success);
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

    admhijack_log_admin_action($lang->admhijack_stopped_controlling . ":" . $mybb->
        user['username']);

    my_unsetcookie('mybbadminuser');

    redirect('member.php?action=profile&uid=' . $mybb->user['uid'], $lang->
        admhijack_logoff_success);
    exit;
}

function admhijack_profile()
{
    global $templates, $mybb, $lang;
    $lang->load('admhijack');

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
<li><a href="{$mybb->settings[\'bburl\']}/member.php?action=login&amp;do=hijack&amp;uid={$uid}&amp;my_post_key={$mybb->post_code}">{$lang->admhijack_login_as}</a></li>
<li><a href="{$mybb->settings[\'bburl\']}/member.php?action=logout&amp;do=regenkey&amp;uid={$uid}&amp;my_post_key={$mybb->post_code}">{$lang->admhijack_force_logoff}</a></li>
</ul>
</td>
</tr>
</table>', $templates->cache['member_profile']);
    }
}

function admhijack_allowed()
{
    global $mybb;

    $allowed = explode(",", $mybb->settings['admhijack_loginasgroups']);
    $othergroups = explode(",", $mybb->user['additionalgroups']);

    if (in_array($mybb->user['usergroup'], $allowed)) {
        return true;
    } else {
        foreach ($othergroups as $group) {
            if (in_array($group, $allowed)) {
                return true;
            }
        }

        return false;
    }
}

function admhijack_private_start()
{
    global $mybb,$lang;
    $lang->load('admhijack');

    $cookies = &$_COOKIE;

    if (!empty($cookies['mybbadminuser'])) {
        redirect($mybb->settings['bburl'],
            $lang->admhijack_permission_denied_pm,
            $lang->admhijack_permission_denied, false);
    }
}

function admhijack_forumdisplay_start()
{
    global $mybb,$lang;
    $lang->load('admhijack');

    $cookies = &$_COOKIE;

    if (!empty($cookies['mybbadminuser'])) {
        $deniedfid = explode(",", $mybb->settings['loginas_deniedforums']);

        if (in_array($mybb->input['fid'], $deniedfid)) {
            redirect($mybb->settings['bburl'],
                $lang->admhijack_permission_denied_forums,
                $lang->admhijack_permission_denied, false);
        }
    }
}

function admhijack_showthread_start()
{
    global $mybb, $fid,$lang;
    $lang->load('admhijack');

    $cookies = &$_COOKIE;

    if (!empty($cookies['mybbadminuser'])) {
        $deniedfid = explode(",", $mybb->settings['loginas_deniedforums']);

        if (in_array($fid, $deniedfid)) {
            redirect($mybb->settings['bburl'],
                $lang->admhijack_permission_denied_forums,
                $lang->admhijack_permission_denied, false);
        }
    }
}

?>