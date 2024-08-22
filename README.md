# fwknop

`TODO` before v1: write all the reference documentation.

## Table of Contents

1. [Description](#description)
2. [Usage - Configuration options and additional functionality](#usage)
3. [Limitations - OS compatibility, etc.](#limitations)

## Description

Install and manage the configuration for fwknop-server.

## Usage

```puppet
# By default, fwknop will just set PCAP_INTF to the
# networking.primary fact.
include fwknop

fwknop::access { 'bob':
  source                    => 'ANY',
  open_ports                => 'tcp/22, tcp/993',
  require_username          => 'bob',
  require_source_address    => true,
  fw_access_timeout_seconds => 30,
  key_base64                => Sensitive('kgohbCga6D5a4YZ0dtbL8SEVbjI1A5KYrRvj0oqcKEk='),
  hmac_key_base64           => Sensitive('Zig9ZYcqj5gYl2S/UpFNp76RlD7SniyN5Ser5WoIKM7zXS28eptWtLcuxCbnh/9R+MjVfUqmqVHqbEyWtHTj4w=='),
}

fwknop::access { 'alice':
  source                    => 'ANY',
  gpg_remote_id             => '7234ABCD',
  gpg_decrypt_id            => 'EBCD1234',
  gpg_allow_no_pw           => true,
  require_source_address    => true,
  require_username          => 'alice',
  fw_access_timeout_seconds => 30,
  hmac_key_base64           => Sensitive('STQ9m03hxj+WXwOpxMuNHQkTAx/EtfAKaXQ3tK8+Azcy2zZpimzRzo4+I53cNZvPJaMBfXjZ9NsB98iOpHY7Tg=='),
}

fwknop::access { 'john':
  source                    => '3.3.3.0/24, 4.4.0.0/16',
  open_ports                => 'tcp/80',
  require_username          => 'john',
  require_source_address    => true,
  fw_access_timeout_seconds => 300,
  key_base64                => Sensitive('bOx25a5kjXf8/TmNQO1IRD3s/E9iLoPaqUbOv8X4VBA='),
  hmac_key_base64           => Sensitive('i0mIhR//1146/T+IMxDVZm1gosNVatvpqpCfkv4X6Xzv4E3SHR6AivCCWk/K/uLDpymyJr95KdEkagfGU4o5yw=='),
}
```

## Limitations

Currently only compatible with latest ubuntu and debian.
