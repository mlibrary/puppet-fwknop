# Copyright (c) 2024 The Regents of the University of Michigan.
# All Rights Reserved. Licensed according to the terms of the Revised
# BSD License. See LICENSE.txt for details.

# fwknop::access
#
# Add a stanza to fwknop's access.conf file.
#
# @example
#   fwknop::access { 'example':
#     source                 => 'ANY',
#     require_source_address => true,
#     key_base64             => Sensitive('Sz80RjpXOlhH2olGuKBUamHKcqyMBsS9BTgLaMugUsg='),
#     hmac_key_base64        => Sensitive('c0TOaMJ2aVPdYTh4Aa25Dwxni7PrLo2zLAtBoVwSepkvH6nLcW45Cjb9zaEC2SQd03kaaV+Ckx3FhCh5ohNM5Q=='),
#   }
#
# @param source
#   This defines the source address from which a SPA packet will be
#   accepted. Every authorization stanza in this file must start with
#   the SOURCE keyword. Networks should be specified in CIDR (e.g.
#   "192.168.10.0/24") notation. Individual IP addresses can be
#   specified as well.
#
#   Also, multiple IP's and/or networks can be defined as a
#   comma-separated list (e.g. "192.168.10.0/24,10.1.1.123").
#
#   The string "ANY" is also accepted if a valid authorization packet
#   should be honored from any source IP.
#
# @param destination
#   This defines the destination address for which a SPA packet
#   will be accepted. Networks should be specified in CIDR (e.g.
#   "192.168.10.0/24") notation. Individual IP addresses can be
#   specified as well.
#
#   Also, multiple IP's and/or networks can be defined as a
#   comma-separated list (e.g. "192.168.10.0/24,10.1.1.123").
#
#   The string "ANY" is also accepted if a valid authorization packet
#   should be honored to any destination IP.
#
# @param open_ports
#   Define a set of ports and protocols (tcp or udp) that are allowed to
#   be opened if a valid SPA packet is received and its access request
#   matches one of the entries here.
#
#   If this entry is not set, then fwknopd will attempt to honor the
#   request specified in the SPA data.
#
# @param restrict_ports
#   Define a set of ports and protocols (tcp or udp) that are *NOT*
#   allowed to be opened even if a valid SPA packet is received.
#
# @param key
#   Define the key used for decrypting an incoming SPA packet that is
#   using its built-in encryption (e.g. not GPG). This parameter is
#   required for all non-GPG-encrypted SPA packets.
#
# @param key_base64
#   Same as the key parameter, but specify the symmetric key as a base64
#   encoded string. This allows non-ascii characters to be included in
#   the base64-decoded key.
#
# @param hmac_key
#   Specify the HMAC key for authenticated encryption of SPA packets.
#   This supports both Rijndael and GPG encryption modes, and is applied
#   according to the encrypt-then-authenticate model.
#
# @param hmac_key_base64
#   Specify the HMAC key as a base64 encoded string. This allows
#   non-ascii characters to be included in the base64-decoded key.
#
# @param fw_access_timeout_seconds
#   Define the length of time access will be granted by fwknop through
#   the firewall after a valid SPA packet is received from the source IP
#   address that matches this stanza's source.
#
#   If fw_access_timeout is not set then a default timeout of 30 seconds
#   will automatically be set.
#
# @param include
#   This processes the access.conf stanzas from an additional file.
#   Complete stanzas should be contained within each file.
#
# @param include_folder
#   This processes all the *.conf files in the specified directory.
#
# @param encryption_mode
#    Specify the encryption mode when AES is used. The default is CBC
#    mode, but other modes can be selected such as OFB and CFB. In
#    general, it is recommended to not use this parameter and leave it
#    as the default. Note that the string "legacy" can be specified in
#    order to generate SPA packets with the old initialization vector
#    strategy used by versions of fwknop before 2.5. With the 2.5
#    release, fwknop uses PBKDF1 for key derivation.
#
# @param hmac_digest_type
#   Specify the digest algorithm for incoming SPA packet authentication.
#   Must be one of MD5, SHA1, SHA256, SHA384, SHA512, SHA3_256, or
#   SHA3_512. This is an optional field, and if not specified then
#   fwknopd defaults to using SHA256 if the access stanza requires an
#   HMAC.
#
# @param access_expire
#   Defines an expiration date for the access stanza in MM/DD/YYYY
#   format. All SPA packets that match an expired stanza will be
#   ignored. This parameter is optional.
#
# @param access_expire_epoch
#   Defines an expiration date for the access stanza as the epoch time,
#   and is useful if a more accurate expiration time needs to be given
#   than the day resolution offered by the access_expire parameter
#   above. All SPA packets that match an expired stanza will be ignored.
#   This parameter is optional.
#
# @param enable_cmd_exec
#   This specifies whether or not fwknopd will accept complete commands
#   that are contained within a SPA packet. Any such command will be
#   executed as user specified using the cmd_exec_user parameter by the
#   fwknopd server. If not set here, the default is false.
#
# @param cmd_exec_user
#   This specifies the user that will execute commands contained within
#   a SPA packet. If not specified, fwknopd will execute it as the user
#   it is running as (most likely root). Setting this to a non-root user
#   is highly recommended.
#
# @param enable_cmd_sudo_exec
#   sudo provides a powerful means of restricting the sets of commands
#   that users can execute via the "sudoers" file. By enabling this
#   feature (and in "enable_cmd_exec" mode), all incoming commands from
#   valid SPA packets will be prefixed by "/path/to/sudo -u <user> -g
#   <group>" where the path to sudo is set by the "sudo_exe" parameter,
#   "<user>" is set by the "cmd_sudo_exec_user" parameter (default is
#   "root" if not set), and "<group>" is set by "cmd_sudo_exec_group"
#   (default is also "root" if not set).
#
# @param cmd_sudo_exec_user
#   Specify the user (via "sudo -u <user>") that will execute a command
#   contained within a SPA packet. If this parameter is not given,
#   fwknopd will assume the command should be executed as root.
#
# @param cmd_exec_group
#   Specify the group (via setgid) that will execute a command contained
#   within a SPA packet. If this parameter is not given, fwknopd will
#   execute the command as the user it is running as (most likely root).
#   Setting this to a non-root user such as "nobody" is highly
#   recommended if elevated permissions are not needed.
#
# @param cmd_sudo_exec_group
#   Specify the group (via "sudo -g <group>") that will execute a
#   command contained within a SPA packet. If this parameter is not
#   given, fwknopd will assume the command should be executed as root.
#
# @param cmd_cycle_open
#   Specify a command open/close cycle to be executed upon receipt of a
#   valid SPA packet. This directive sets the initial command, and is
#   meant to be used in conjunction with the "cmd_cycle_close" parameter
#   below. The main application of this feature is to allow fwknopd to
#   interact with firewall or ACL's that are not natively supported, and
#   facilitate the same access model as for the main supported firewalls
#   such as iptables. That is, a command is executed to open the
#   firewall or ACL, and then a corresponding close command is executed
#   after a timer expires. Both the "cmd_cycle_open" and
#   "cmd_cycle_close" parameters support special substitution strings to
#   allow values to be taken from the SPA payload and used on the
#   command line of the executed command. These strings begin with a "$"
#   character, and include "$IP" (the allow IP decrypted from the SPA
#   payload), "$SRC" (synonym for "$IP") , "$PKT_SRC" (the source IP in
#   the network layer header of the SPA packet), "$DST" (the destination
#   IP), "$PORT" (the allow port), and "$PROTO" (the allow protocol),
#   "$TIMEOUT" (set the client timeout if specified).
#
# @param cmd_cycle_close
#   Specify the close command that corresponds to the open command set
#   by the "cmd_cycle_open" parameter. The same string substitutions
#   such as "$IP", "$PORT", and "$PROTO" are supported. In addition, the
#   special value "NONE" can be set to allow no close command to be
#   executed after the open command. This might be handy in certain
#   situations where, say, indefinite access is desired and allowed.
#
# @param cmd_cycle_timer_seconds
#   Set the number of seconds after which the close command set in
#   "cmd_cycle_close" will be executed. This defines the open/close
#   timer interval.
#
# @param sudo_exe
#   Define the path to the sudo binary. Default is "/usr/bin/sudo".
#
# @param require_username
#   Require a specific username from the client system as encoded in the
#   SPA data. This parameter is optional and if not specified, the
#   username data in the SPA data is ignored.
#
# @param require_source_address
#   Force all SPA packets to contain a real IP address within the
#   encrypted data. This makes it impossible to use the "-s" command
#   line argument on the fwknop client command line, so either "-R" has
#   to be used to automatically resolve the external address (if the
#   client is behind a NAT) or the client must know the external IP. If
#   not set here, the default is false.
#
# @param force_nat
#   For any valid SPA packet, force the requested connection to be NAT'd
#   through to the specified (usually internal) IP and port value. This
#   is useful if there are multiple internal systems running a service
#   such as SSHD, and you want to give transparent access to only one
#   internal system for each stanza in the access.conf file. This way,
#   multiple external users can each directly access only one internal
#   system per SPA key.
#
# @param force_snat
#   For any valid SPA packet, add an SNAT rule in addition to any DNAT
#   rule created with a corresponding (required) force_nat parameter.
#   This is analogous to the "fwknop::snat_translate_ip" parameter
#   except that it is per access stanza and overrides any value set with
#   "fwknop::snat_translate_ip". This is useful for situations where an
#   incoming NAT'd connection may be otherwise unanswerable due to
#   routing constraints (i.e. the system receiving the SPA authenticated
#   connection has a default route to a different device than the SPA
#   system itself).
#
# @param force_masquerade
#   This is similar to the "force_snat" parameter, except that it is not
#   necessary to also specify an IP address for SNAT rules because the
#   MASQUERADE target is used instead.
#
# @param forward_all
#   In NAT scenarios, control whether all traffic is forwarded through
#   the fwknopd system as opposed to just forwarding connections to
#   specific services as requested by the fwknop client.
#
# @param disable_dnat
#   Control whether DNAT rules are created in force_nat scenarios. This
#   is mainly used in conjunction with the forward_all parameter to
#   allow fwknopd to act essentially as an SPA gateway. I.e., the fwknop
#   client is used to gain access via SPA to the broader Internet after
#   being granted an IP via DHCP, but prior to sending the SPA packet
#   all traffic is blocked by default to the Internet.
#
# @param gpg_decrypt_id
#   Define a GnuPG key ID to use for decrypting SPA messages that have
#   been encrypted by an fwknop client using GPG. This keyword is
#   required for authentication that is based on gpg keys. The gpg key
#   ring on the client must have imported and signed the fwknopd server
#   key, and vice versa.
#
#   It is ok to use a sensitive personal gpg key on the client, but each
#   fwknopd server should have its own gpg key that is generated
#   specifically for fwknop communications. The reason for this is that
#   this decryption password within this file.
#
#   Note that you can use either keyID or its corresponding email address.
#
#   For more information on using fwknop with GnuPG keys, see the
#   following link: http://www.cipherdyne.org/fwknop/docs/gpghowto.html
#
# @param gpg_decrypt_pw
#   Specify the decryption password for the gpg key defined by the
#   gpg_decrypt_id parameter. This is a required field for gpg-based
#   authentication.
#
# @param gpg_allow_no_pw
#   Allow fwknopd to leverage a GnuPG key pair that does not have an
#   associated password. While this may sound like a controversial
#   deployment mode, in automated environments it makes sense because
#   "there is usually no way to store a password more securely than on
#   the secret keyring itself" according to:
#   "http://www.gnupg.org/faq/GnuPG-FAQ.html#how-can-i-use-gnupg-in-an-automated-environment".
#   Using this feature and removing the passphrase from a GnuPG key pair
#   is useful in some environments where libgpgme is forced to use
#   gpg-agent and/or pinentry to collect a passphrase.
#
# @param gpg_require_sig
#   With this setting set to true, fwknopd check all GPG-encrypted SPA
#   messages for a signature (signed by the sender's key). If the
#   incoming message is not signed, the decryption process will fail.
#   If not set, the default is false.
#
# @param gpg_disable_sig
#   Disable signature verification for incoming SPA messages. This is
#   not a recommended setting, and the default is false.
#
# @param gpg_ignore_sig_verify_error
#   Setting this will allow fwknopd to accept incoming GPG-encrypted
#   packets that are signed, but the signature did not pass verification
#   (i.e. the signer key was expired, etc.). This setting only applies
#   if the gpg_require_sig parameter is also set to true.
#
# @param gpg_remote_id
#   Define a list of gpg key ID's that are required to have signed any
#   incoming SPA messages that have been encrypted with the fwknopd
#   server key. This ensures that the verification of the remote user
#   is accomplished via a strong cryptographic mechanism. This setting
#   only applies if the gpg_require_sig is set to true.
#
# @param gpg_fingerprint_id
#   Specify a set of full-length GnuPG key fingerprints instead of the
#   shorter key identifiers set with the "gpg_remote_id" parameter. Here
#   is an example fingerprint for one of the fwknop test suite keys:
#   00CC95F05BC146B6AC4038C9E36F443C6A3FAD56.
#
# @param gpg_home_dir
#   Define the path to the GnuPG directory to be used by fwknopd. If
#   this keyword is not specified here, then fwknopd will default to
#   using the "/root/.gnupg" directory for the server key(s).
#
# @param gpg_exe
#   Define the path to the GnuPG executable. If this keyword is not
#   specified then fwknopd will default to using /usr/bin/gpg.
#
# @param order
#   Reorders your access stanzas within the access.conf. Stanzas that
#   share the same order number are ordered by name. Default is '10'.
#
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
