<?php
define('WP_INSTALLING', true);
require_once dirname(__DIR__) . '/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/upgrade.php';

function go_home()
{
    header('Refresh: 3; url=/', true, 302);
}

if (is_blog_installed()) {
    go_home();
    die("<h1>WordPress is already installed.</h1>");
}

$weblog_title = 'My Blog';
$user_name = 'admin';
$admin_email = 'admin@example.com';
$admin_password = 'admin';
$public = 1;
$language = 'en';
$result = wp_install($weblog_title, $user_name, $admin_email, $public, '', wp_slash($admin_password), $language);
go_home();
echo '<h1>Installation Result</h1>';
echo '<pre>';
var_dump($result);
echo '</pre>';
