# Aegis Backup Decryptor

[![Ruby](https://img.shields.io/badge/Ruby-CC342D?style=for-the-badge&logo=ruby&logoColor=white)](https://ruby-lang.org)
[![Coveralls](https://img.shields.io/coverallsCoverage/github/elliotwutingfeng/aegis-backup-decryptor?logo=coveralls&style=for-the-badge)](https://coveralls.io/github/elliotwutingfeng/aegis-backup-decryptor?branch=main)
[![GitHub license](https://img.shields.io/badge/LICENSE-GPLv3-GREEN?style=for-the-badge)](LICENSE)

CLI tool to decrypt backup files exported from the [Aegis Authenticator app](https://getaegis.app).

This application is neither affiliated with Beem Development nor Aegis Authenticator.

## Requirements

- **Ruby:** 2.5+/3.0+, no external gems needed
- **OpenSSL:** 1.1+/3.0+
  - In the terminal, run the following to view your Ruby interpreter's [OpenSSL](https://openssl.org) version

    ```bash
    ruby -e "require 'openssl'; puts OpenSSL::OPENSSL_LIBRARY_VERSION"
    # Example output
    # OpenSSL 3.4.0 22 Oct 2024
    ```

  - [LibreSSL](https://libressl.org) is not supported

- **OS:** Either Windows, macOS, or Linux

### Safety

> [!CAUTION]
> This program writes the backup file content to stdout in plaintext. By default, this means the content will be displayed on the screen.
>
> **Recommended precautions:**
>
> - Do NOT decrypt your backup file in public areas, or in the presence of untrusted persons and surveillance cameras.
> - Do NOT decrypt your backup file on a machine that you suspect to be infected by malware.
> - ENSURE that your terminal session output is not being unintentionally saved or recorded.

## Example

**File:** `test/encrypted_test.json`

**Password:** `test`

```bash
# Enter the above password when prompted
ruby lib/decrypt.rb test/encrypted_test.json
```

You should get the following plaintext JSON output.

```json
{
    "version": 1,
    "entries": [
        {
            "type": "totp",
            "uuid": "3ae6f1ad-2e65-4ed2-a953-1ec0dff2386d",
            "name": "Mason",
            "issuer": "Deno",
            "icon": null,
            "info": {
                "secret": "4SJHB4GSD43FZBAI7C2HLRJGPQ",
                "algo": "SHA1",
                "digits": 6,
                "period": 30
            }
        },
        {
            "type": "totp",
            "uuid": "84b55971-a3d2-4173-a5bb-0aea113dbc17",
            "name": "James",
            "issuer": "SPDX",
            "icon": null,
            "info": {
                "secret": "5OM4WOOGPLQEF6UGN3CPEOOLWU",
                "algo": "SHA256",
                "digits": 7,
                "period": 20
            }
        },
        {
            "type": "totp",
            "uuid": "3deaff2e-f181-4837-80e1-fdf0c54e9363",
            "name": "Elijah",
            "issuer": "Airbnb",
            "icon": null,
            "info": {
                "secret": "7ELGJSGXNCCTV3O6LKJWYFV2RA",
                "algo": "SHA512",
                "digits": 8,
                "period": 50
            }
        },
        {
            "type": "hotp",
            "uuid": "0a8c0571-ff6f-4b02-aa4b-50553b4fb4fe",
            "name": "James",
            "issuer": "Issuu",
            "icon": null,
            "info": {
                "secret": "YOOMIXWS5GN6RTBPUFFWKTW5M4",
                "algo": "SHA1",
                "digits": 6,
                "counter": 1
            }
        },
        {
            "type": "hotp",
            "uuid": "03e572f2-8ebd-44b0-a57e-e958af74815d",
            "name": "Benjamin",
            "issuer": "Air Canada",
            "icon": null,
            "info": {
                "secret": "KUVJJOM753IHTNDSZVCNKL7GII",
                "algo": "SHA256",
                "digits": 7,
                "counter": 50
            }
        },
        {
            "type": "hotp",
            "uuid": "b25f8815-007f-40f7-a700-ce058ac05435",
            "name": "Mason",
            "issuer": "WWE",
            "icon": null,
            "info": {
                "secret": "5VAML3X35THCEBVRLV24CGBKOY",
                "algo": "SHA512",
                "digits": 8,
                "counter": 10300
            }
        },
        {
            "type": "steam",
            "uuid": "5b11ae3b-6fc3-4d46-8ca7-cf0aea7de920",
            "name": "Sophia",
            "issuer": "Boeing",
            "icon": null,
            "info": {
                "secret": "JRZCL47CMXVOQMNPZR2F7J4RGI",
                "algo": "SHA1",
                "digits": 5,
                "period": 30
            }
        }
    ]
}
```

### Other formats

You can also add the `-f / --format` option to print the plaintext output as `csv` or as a `pretty` CSV-like String padded with spaces.

#### csv

```bash
# Enter the above password when prompted
ruby lib/decrypt.rb test/encrypted_test.json -f csv
```

```csv
uuid,type,name,issuer,info.secret,info.period,info.digits,info.counter,info.algo,icon
3ae6f1ad-2e65-4ed2-a953-1ec0dff2386d,totp,Mason,Deno,4SJHB4GSD43FZBAI7C2HLRJGPQ,30,6,,SHA1,
84b55971-a3d2-4173-a5bb-0aea113dbc17,totp,James,SPDX,5OM4WOOGPLQEF6UGN3CPEOOLWU,20,7,,SHA256,
3deaff2e-f181-4837-80e1-fdf0c54e9363,totp,Elijah,Airbnb,7ELGJSGXNCCTV3O6LKJWYFV2RA,50,8,,SHA512,
0a8c0571-ff6f-4b02-aa4b-50553b4fb4fe,hotp,James,Issuu,YOOMIXWS5GN6RTBPUFFWKTW5M4,,6,1,SHA1,
03e572f2-8ebd-44b0-a57e-e958af74815d,hotp,Benjamin,Air Canada,KUVJJOM753IHTNDSZVCNKL7GII,,7,50,SHA256,
b25f8815-007f-40f7-a700-ce058ac05435,hotp,Mason,WWE,5VAML3X35THCEBVRLV24CGBKOY,,8,10300,SHA512,
5b11ae3b-6fc3-4d46-8ca7-cf0aea7de920,steam,Sophia,Boeing,JRZCL47CMXVOQMNPZR2F7J4RGI,30,5,,SHA1,
```

#### pretty

```bash
# Enter the above password when prompted
ruby lib/decrypt.rb test/encrypted_test.json -f pretty
```

```csv
uuid                                  type   name      issuer      info.secret                 info.period  info.digits  info.counter  info.algo  icon
3ae6f1ad-2e65-4ed2-a953-1ec0dff2386d  totp   Mason     Deno        4SJHB4GSD43FZBAI7C2HLRJGPQ  30           6                          SHA1
84b55971-a3d2-4173-a5bb-0aea113dbc17  totp   James     SPDX        5OM4WOOGPLQEF6UGN3CPEOOLWU  20           7                          SHA256
3deaff2e-f181-4837-80e1-fdf0c54e9363  totp   Elijah    Airbnb      7ELGJSGXNCCTV3O6LKJWYFV2RA  50           8                          SHA512
0a8c0571-ff6f-4b02-aa4b-50553b4fb4fe  hotp   James     Issuu       YOOMIXWS5GN6RTBPUFFWKTW5M4               6            1             SHA1
03e572f2-8ebd-44b0-a57e-e958af74815d  hotp   Benjamin  Air Canada  KUVJJOM753IHTNDSZVCNKL7GII               7            50            SHA256
b25f8815-007f-40f7-a700-ce058ac05435  hotp   Mason     WWE         5VAML3X35THCEBVRLV24CGBKOY               8            10300         SHA512
5b11ae3b-6fc3-4d46-8ca7-cf0aea7de920  steam  Sophia    Boeing      JRZCL47CMXVOQMNPZR2F7J4RGI  30           5                          SHA1
```

### Hiding unwanted fields

When the `-f / --format` option is set to `csv` or `pretty`, you can use the `-e / --except` option to hide unwanted fields. Non-existent fields are silently ignored.

```bash
# Enter the above password when prompted
ruby lib/decrypt.rb test/encrypted_test.json -f pretty -e icon,icon_mime,icon_hash,favorite,note,uuid
```

```csv
type   name      issuer      info.secret                 info.period  info.digits  info.counter  info.algo
totp   Mason     Deno        4SJHB4GSD43FZBAI7C2HLRJGPQ  30           6                          SHA1
totp   James     SPDX        5OM4WOOGPLQEF6UGN3CPEOOLWU  20           7                          SHA256
totp   Elijah    Airbnb      7ELGJSGXNCCTV3O6LKJWYFV2RA  50           8                          SHA512
hotp   James     Issuu       YOOMIXWS5GN6RTBPUFFWKTW5M4               6            1             SHA1
hotp   Benjamin  Air Canada  KUVJJOM753IHTNDSZVCNKL7GII               7            50            SHA256
hotp   Mason     WWE         5VAML3X35THCEBVRLV24CGBKOY               8            10300         SHA512
steam  Sophia    Boeing      JRZCL47CMXVOQMNPZR2F7J4RGI  30           5                          SHA1
```

## Testing

```bash
gem install bundler
bundle install
bundle exec rspec -r spec_helper
```

## Vendoring Bundled Gems

```bash
rm -rf vendor/
gem unpack csv --target=vendor/gems/
```

Then update gem versions in Gemfile, and run `bundle install`.
