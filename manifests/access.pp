# Copyright (c) 2024 The Regents of the University of Michigan.
# All Rights Reserved. Licensed according to the terms of the Revised
# BSD License. See LICENSE.txt for details.

# @summary A short summary of the purpose of this defined type.
#
# A description of what this defined type does
#
# @example
#   fwknop::access { 'namevar': }
# @param source Later
# @param destination Later
# @param open_ports Later
# @param restrict_ports Later
# @param key Later
# @param key_base64 Later
# @param hmac_key Later
# @param hmac_key_base64 Later
# @param fw_access_timeout_seconds Later
# @param include Later
# @param include_folder Later
# @param encryption_mode Later
# @param hmac_digest_type Later
# @param access_expire Later
# @param access_expire_epoch Later
# @param enable_cmd_exec Later
# @param enable_cmd_sudo_exec Later
# @param cmd_exec_user Later
# @param cmd_sudo_exec_user Later
# @param cmd_exec_group Later
# @param cmd_sudo_exec_group Later
# @param cmd_cycle_open Later
# @param cmd_cycle_close Later
# @param cmd_cycle_timer_seconds Later
# @param sudo_exe Later
# @param require_username Later
# @param require_source_address Later
# @param force_nat Later
# @param force_snat Later
# @param force_masquerade Later
# @param forward_all Later
# @param disable_dnat Later
# @param gpg_decrypt_id Later
# @param gpg_decrypt_pw Later
# @param gpg_allow_no_pw Later
# @param gpg_require_sig Later
# @param gpg_disable_sig Later
# @param gpg_ignore_sig_verify_error Later
# @param gpg_remote_id Later
# @param gpg_fingerprint_id Later
# @param gpg_home_dir Later
# @param gpg_exe Later
# @param order Later
define fwknop::access (
  String $source = 'ANY',
  Optional[String] $destination = undef,
  Optional[String] $open_ports = undef,
  Optional[String] $restrict_ports = undef,
  Optional[Variant[String, Sensitive[String]]] $key = undef,
  Optional[Variant[String, Sensitive[String]]] $key_base64 = undef,
  Optional[Variant[String, Sensitive[String]]] $hmac_key = undef,
  Optional[Variant[String, Sensitive[String]]] $hmac_key_base64 = undef,
  Optional[Integer] $fw_access_timeout_seconds = undef,
  Optional[String] $include = undef,
  Optional[String] $include_folder = undef,
  Optional[String] $encryption_mode = undef,
  Optional[String] $hmac_digest_type = undef,
  Optional[String] $access_expire = undef,
  Optional[Integer] $access_expire_epoch = undef,
  Optional[Boolean] $enable_cmd_exec = undef,
  Optional[Boolean] $enable_cmd_sudo_exec = undef,
  Optional[String] $cmd_exec_user = undef,
  Optional[String] $cmd_sudo_exec_user = undef,
  Optional[String] $cmd_exec_group = undef,
  Optional[String] $cmd_sudo_exec_group = undef,
  Optional[String] $cmd_cycle_open = undef,
  Optional[String] $cmd_cycle_close = undef,
  Optional[Integer] $cmd_cycle_timer_seconds = undef,
  Optional[String] $sudo_exe = undef,
  Optional[String] $require_username = undef,
  Optional[Boolean] $require_source_address = undef,
  Optional[String] $force_nat = undef,
  Optional[String] $force_snat = undef,
  Optional[Boolean] $force_masquerade = undef,
  Optional[Boolean] $forward_all = undef,
  Optional[Boolean] $disable_dnat = undef,
  Optional[String] $gpg_decrypt_id = undef,
  Optional[Variant[String, Sensitive[String]]] $gpg_decrypt_pw = undef,
  Optional[Boolean] $gpg_allow_no_pw = undef,
  Optional[Boolean] $gpg_require_sig = undef,
  Optional[Boolean] $gpg_disable_sig = undef,
  Optional[Boolean] $gpg_ignore_sig_verify_error = undef,
  Optional[String] $gpg_remote_id = undef,
  Optional[String] $gpg_fingerprint_id = undef,
  Optional[String] $gpg_home_dir = undef,
  Optional[String] $gpg_exe = undef,
  Variant[String, Integer] $order = '10',
) {
  if $key == undef and $key_base64 == undef and $gpg_decrypt_id == undef {
    fail('Must set one (and only one) of: key, key_base64, or gpg_decrypt_id')
  } elsif $key != undef and ($key_base64 != undef or $gpg_decrypt_id != undef) {
    fail('Must set one (and only one) of: key, key_base64, or gpg_decrypt_id')
  } elsif $key_base64 != undef and ($key != undef or $gpg_decrypt_id != undef) {
    fail('Must set one (and only one) of: key, key_base64, or gpg_decrypt_id')
  } elsif $gpg_decrypt_id != undef and ($key != undef or $key_base64 != undef) {
    fail('Must set one (and only one) of: key, key_base64, or gpg_decrypt_id')
  }

  if $gpg_decrypt_id != undef and $gpg_allow_no_pw != true and $gpg_decrypt_pw == undef {
    fail('gpg_decrypt_pw is required for gpg-based authentication')
  }

  $plain_key = $key ? {
    Sensitive => $key.unwrap,
    default   => $key,
  }

  $plain_key_base64 = $key_base64 ? {
    Sensitive => $key_base64.unwrap,
    default   => $key_base64,
  }

  $plain_hmac_key = $hmac_key ? {
    Sensitive => $hmac_key.unwrap,
    default   => $hmac_key,
  }

  $plain_hmac_key_base64 = $hmac_key_base64 ? {
    Sensitive => $hmac_key_base64.unwrap,
    default   => $hmac_key_base64,
  }

  $plain_gpg_decrypt_pw = $gpg_decrypt_pw ? {
    Sensitive => $gpg_decrypt_pw.unwrap,
    default   => $gpg_decrypt_pw,
  }

  concat::fragment { "fwknop access ${title}":
    target  => '/etc/fwknop/access.conf',
    content => template('fwknop/access.conf.erb'),
    order   => $order,
  }
}
