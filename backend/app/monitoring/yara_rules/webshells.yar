/*
 * TrustData CyberWatch - web shell and backdoor patterns (PHP).
 *
 * Heuristic rules: a match means "suspicious, needs human review", never "confirmed malware".
 * Each rule has a description shown to the customer. Keep rules specific enough that ordinary
 * CMS code (WordPress, Joomla, Laravel) does not match; add a regression test for every change.
 */

rule php_eval_of_decoded_payload
{
    meta:
        description = "PHP code that decodes hidden data and immediately executes it (eval of base64/gzinflate/rot13 output), the most common way web shells hide their code."
    strings:
        $a = /eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|rawurldecode|hex2bin)\s*\(/ nocase
        $b = /assert\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(/ nocase
    condition:
        any of them
}

rule php_request_input_to_command_execution
{
    meta:
        description = "PHP passes data from the web request straight to a system command or code execution function, letting an attacker run commands on the server."
    strings:
        $a = /(system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|assert|eval)\s*\(\s*(stripslashes\s*\(\s*)?\$_(GET|POST|REQUEST|COOKIE|SERVER)\s*\[/ nocase
        $b = /`\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[/
    condition:
        any of them
}

rule php_preg_replace_eval_modifier
{
    meta:
        description = "preg_replace with the /e modifier executes the replacement as PHP code; removed from PHP years ago and now almost only seen in backdoors."
    strings:
        $a = /preg_replace\s*\(\s*["'][^"']{1,200}\/[a-df-z]*e[a-z]*["']\s*,/ nocase
    condition:
        $a
}

rule php_dynamic_function_from_request
{
    meta:
        description = "Builds and calls a function whose name or body comes from the web request (create_function / variable function), a common backdoor pattern."
    strings:
        $a = /create_function\s*\([^)]{0,200}\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $b = /\$_(GET|POST|REQUEST|COOKIE)\s*\[[^\]]{1,40}\]\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
    condition:
        any of them
}

rule php_known_webshell_markers
{
    meta:
        description = "Contains identifying text of a well-known PHP web shell family (WSO/FilesMan, b374k, c99, r57, IndoXploit, Alfa)."
    strings:
        $wso = "FilesMan" ascii
        $wso2 = "WSO " ascii
        $b374k = "b374k" ascii nocase
        $c99 = "c99shell" ascii nocase
        $r57 = "r57shell" ascii nocase
        $indo = "IndoXploit" ascii nocase
        $alfa = "AlfaTeam" ascii nocase
        $php = "<?php" ascii nocase
    condition:
        $php and any of ($wso, $wso2, $b374k, $c99, $r57, $indo, $alfa)
}

rule php_large_encoded_blob_with_execution
{
    meta:
        description = "A very long encoded string together with code that decodes and executes it: typical of packed or obfuscated malware."
    strings:
        // YARA cannot match very long repetitions, so look for a quoted 200-character run in a large PHP file.
        $blob = /["'][A-Za-z0-9+\/]{200}/
        $php = "<?php" ascii nocase
        $exec1 = "eval" ascii nocase
        $exec2 = "assert" ascii nocase
        $dec1 = "base64_decode" ascii nocase
        $dec2 = "gzinflate" ascii nocase
    condition:
        filesize > 4KB and $php and $blob and any of ($exec1, $exec2) and any of ($dec1, $dec2)
}
